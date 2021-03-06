#!/usr/bin/env python2

import glob
import json
import logging
import logging.handlers
import os
import re
import socket
import struct
import sys
from argparse import ArgumentParser as Parser
from subprocess import (
    Popen, PIPE,
)

import ConfigParser

"""
 @original-author Milosz Galazka
 @author Martijn van Maurik
 @ref-url https://blog.sleeplessbeastie.eu/2019/04/01/how-to-display-php-fpm-pool-information-using-unix-socket-and
 -python-script/

 Changed some extra socket_path detection to allow either inet or unix sockets.
"""

class FCGIStatusClient(object):
    # FCGI protocol version
    FCGI_VERSION = 1

    # FCGI record types
    FCGI_BEGIN_REQUEST = 1
    FCGI_PARAMS = 4

    # FCGI roles
    FCGI_RESPONDER = 1

    # FCGI header length
    FCGI_HEADER_LENGTH = 8

    socket_timeout = None
    raw_status_data = None
    fcgi_begin_request = None
    fcgi_params = None
    status_data = None

    def __init__(self, logger=None, socket_path="/run/php/php7.0-fpm.sock", socket_timeout=5.0,
                 status_path="/fpm-status"):
        self.logger = logger

        if os.path.exists(socket_path):
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket_path = socket_path
        self.status_path = status_path
        self.set_socket_timeout(socket_timeout)
        self.request_id = 1

        self.params = {
            "SCRIPT_NAME":    status_path, "SCRIPT_FILENAME": status_path, "QUERY_STRING": "json&full",
            "REQUEST_METHOD": "GET",
        }

    def set_socket_timeout(self, timeout):
        self.socket_timeout = timeout
        self.socket.settimeout(self.socket_timeout)

    def connect(self):
        try:
            if os.path.exists(self.socket_path):
                if not os.access(self.socket_path, os.W_OK):
                    raise Exception('no read and/or write access to %s' % (self.socket_path))
                self.socket.connect(self.socket_path)
            else:
                host, _, port = self.socket_path.partition(':')
                self.socket.connect((host, int(port)))

        except Exception as e:
            self.logger.error("Can not connect to socket: %s" % (e))
            sys.exit(2)

    def close(self):
        self.socket.close()

    def define_begin_request(self):
        fcgi_begin_request = struct.pack("!HB5x", self.FCGI_RESPONDER, 0)
        fcgi_header = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_BEGIN_REQUEST, self.request_id,
                                  len(fcgi_begin_request), 0)
        self.fcgi_begin_request = fcgi_header + fcgi_begin_request

    def define_parameters(self):
        parameters = []
        for name, value in self.params.items():
            parameters.append(chr(len(name)) + chr(len(value)) + name + value)

        parameters = ''.join(parameters)
        parameters_length = len(parameters)
        parameters_padding_req = parameters_length & 7
        parameters_padding = b'\x00' * parameters_padding_req

        fcgi_header_start = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_PARAMS, self.request_id,
                                        parameters_length, parameters_padding_req)
        fcgi_header_end = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_PARAMS, self.request_id, 0, 0)
        self.fcgi_params = fcgi_header_start + parameters.encode() + parameters_padding + fcgi_header_end

    def execute(self):
        try:
            self.socket.send(self.fcgi_begin_request)
            self.socket.send(self.fcgi_params)

            header = self.socket.recv(self.FCGI_HEADER_LENGTH)
            fcgi_version, request_type, request_id, request_length, request_padding = struct.unpack("!BBHHBx", header)

            if request_type == 6:
                self.raw_status_data = self.socket.recv(request_length)
            else:
                self.raw_status_data = ""
                if request_type == 7:
                    raise Exception("Received an error packet. (%s does not exist)" % self.status_path)
                else:
                    raise Exception("Received unexpected packet type.")
        except:
            self.logger.error(sys.exc_info()[1])
            sys.exit(2)

        self.status_data = self.raw_status_data.decode().split("\r\n\r\n")[1]

    def make_request(self):
        self.define_begin_request()
        self.define_parameters()
        self.connect()
        self.execute()
        self.close()

    def print_status(self):
        print(json.dumps(self.status_data))

    def get_status(self):
        dstatus = json.loads(self.status_data)

        status = {
            'active_processes':     dstatus.get('active processes'), 'accepted_conn': dstatus.get('accepted conn'),
            'process_manager':      dstatus.get('process manager'), 'listen_queue': dstatus.get('listen queue'),
            'start_since':          dstatus.get('start since'), 'idle_processes': dstatus.get('idle processes'),
            'start_time':           dstatus.get('start time'), 'slow_requests': dstatus.get('slow requests'),
            'max_active_processes': dstatus.get('max active processes'),
            'max_children_reached': dstatus.get('max children reached'),
            'max_listen_queue':     dstatus.get('max listen queue'), 'total_processes': dstatus.get('total processes'),
            'listen_queue_len':     dstatus.get('listen queue len'), 'pool': dstatus.get('pool'),
        }

        return status


"""
 @author Martijn van Maurik
 
 Zabbix class wrapper to send the data to traps in Zabbix
"""


class ZabbixPHPFPM:
    logger = None
    _opts = None
    searchable_paths = [  # support for opensuse dev
        '/etc/php7/fpm/php-fpm.d/*.conf',

        # Debian based php fpm configs
        '/etc/php5/fpm/pool.d/*.conf', '/etc/php/*/fpm/pool.d/*.conf', ]

    @property
    def opts(self):
        if self._opts is None:
            parser = Parser(version="%(prog)s version v0.3", prog=os.path.basename(__file__), description="""This 
            program gathers data from PHP-FPM's
            built-in status page and sends it to
            Zabbix. The data is sent via zabbix_sender.
            License: GPLv2
        """, )

            parser.add_argument("--dry-run", action="store_true", dest="dryrun", default=False,
                                help="Do not send data to zabbix")
            parser.add_argument("--discover", action="store_true", dest="discover", default=False,
                                help="Discover pools", )
            parser.add_argument("-V", "--verbose", action="store_true", dest="verbose", default=False,
                                help="Set output to stdout (default: %(default)s)", )
            parser.add_argument("-D", "--debug", action="store_true", dest="debug", default=False,
                                help="Print debug information. (default: %(default)s)", )
            parser.add_argument("-s", "--sender", action="store", dest="senderloc", default="/usr/bin/zabbix_sender",
                                help="Location to the zabbix_sender executable. (default: %(default)s)", )
            parser.add_argument("-z", "--zabbixserver", action="store", dest="zabbixserver", default="localhost",
                                help="Zabbix trapper hostname (default: %(default)s)", )
            parser.add_argument("-q", "--zabbixport", action="store", type=int, dest="zabbixport", default=10051,
                                help="Zabbix trapper port to connect to. (default: %(default)s)", )
            parser.add_argument("-c", "--zabbixsource", action="store", dest="zabbixsource", default="localhost",
                                help="Zabbix host to use when sending values. (default: %(default)s)", )
            parser.add_argument("--config", action="store", dest="agentconfig", default=None,
                                help="zabbix agent config to derive Hostname and ServerActive from. (default: %("
                                     "default)s)", )
            parser.add_argument("-k", "--key", action="store", dest="zabbix_key", default=None,
                                help="Use Zabbix pool key name (default: %(default)s)", )

            # PHP-FPM specific
            parser.add_argument("-S", "--socket", action="store", dest="socket_path",
                                default='/run/php/php7.0-fpm.sock',
                                help="PHP-FPM: use socket (/run/php/file.sock or ip:port) (default: %(default)s)", )
            parser.add_argument("-P", "--path", action="store", dest="status_path", default='/fpm-status',
                                help="PHP-FPM: status path (default: %(default)s)", )

            self._opts = parser.parse_args()

        return self._opts

    def zabbix_sender(self, payload, agentconfig=None, zabbixserver=None, zabbixport=10051,
                      senderloc='/usr/bin/zabbix_sender'):
        sender_command = []
        result = 0
        err = ''
        ret = 1
        out = ''

        if not (os.path.exists(senderloc)) or not (os.access(senderloc, os.X_OK)):
            self.logger.error("%s not exists or not executable" % (senderloc))

            raise Exception("%s not exists or not executable" % (senderloc))

        else:
            if agentconfig is not None:
                self.logger.debug('sending to server in agent config %s' % agentconfig)
                sender_command = [senderloc, '-vv', '--config', agentconfig, '--input-file', '-']
            else:
                if zabbixserver is not None:
                    self.logger.debug('sending to server %s:%s' % (zabbixserver, zabbixport))
                    sender_command = [senderloc, '-vv', '--zabbix-server', zabbixserver, '--port', str(zabbixport),
                                      '--input-file', '-']
                else:
                    self.logger.error('must specify agent configuration or server name to call zabbix_sender with')

            try:
                self.logger.debug('Payload:\n%s' % (payload))

                if self.opts.dryrun:
                    ret = result = 0

                    return 1

                p = Popen(sender_command, stdout=PIPE, stdin=PIPE, stderr=PIPE)
                out, err = p.communicate(input=payload)
                ret = p.wait()
                result = 1
            except Exception as e:
                err = "%s\nFailed to execute: '%s'" % (e, " ".join(sender_command))
            finally:
                if ret != 0:
                    raise Exception("error returned from %s! ret: %d, out: '%s', err: '%s'" % (
                        sender_command[0], ret, out.strip('\n'), err.strip('\n')))

        return result

    @staticmethod
    def set_log_level(loglevel):
        """
            Setup logging.
            """

        numeric_loglevel = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_loglevel, int):
            raise ValueError('Invalid log level: "%s"\n Try: "debug", "info", "warning", "critical".' % loglevel)

        program = os.path.basename(__file__)
        logger = logging.getLogger(program)
        logger.setLevel(numeric_loglevel)


        return logger

    def get_payload(self, status):
        pool = status.get('pool')
        payload = ''
        zabbix_key = self.opts.zabbix_key if self.opts.zabbix_key else '%s-%s' % (
            pool, self._get_zabbix_suffix_key(self.opts.socket_path),)

        if self.opts.agentconfig:
            for item, value in status.items():
                payload += "-\tphp-fpm.%s[%s]\t%s\n" % (item, zabbix_key, value,)
        else:
            for item, value in status.items():
                payload += "%s php-fpm.%s[%s] %s\n" % (self.opts.zabbixsource, item, zabbix_key, value,)

        return payload

    @staticmethod
    def _get_zabbix_suffix_key(listen):
        if os.path.exists(listen):
            x = re.match(r'/run/php/(?P<version>\S+)-(?P<pool>\w+)-fpm.sock', listen)
            suffix = x.group('version') if x else ''
        else:
            x = re.match(r'(?P<host>[^:]+):(?P<port>\d+)$', listen)
            suffix = '%s-%s' % (x.group('host'), x.group('port')) if x else ''

        return suffix

    def autodiscover(self):
        data = {
            'data': [],
        }

        for s in self.searchable_paths:
            configs = glob.glob(s)

            config = ConfigParser.SafeConfigParser(allow_no_value=True)
            for conf in configs:
                config.read(conf)

            for section in config.sections():
                try:
                    listen = config.get(section, 'listen')

                    if config.has_option(section, 'pm.status_path'):
                        if re.match(r'/run/php/(?P<version>\S+)-(?P<pool>\w+)-fpm.sock', listen):
                            if not os.path.exists(listen):
                                raise Exception('The socket %s does not exist!' % (listen))
                            if not os.access(listen, os.W_OK):
                                raise Exception('The user has no permission no to read and/or write %s' % (listen))
                        else:
                            x = re.match(r'(?P<host>[^:]+):(?P<port>\d+)$', listen)
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            result = sock.connect_ex((x.group('host'), int(x.group('port')),))
                            sock.close()
                            if result != 0:
                                raise Exception('Can not connect to %s:%s' % (x.group('host'), x.group('port'),))

                        suffix = self._get_zabbix_suffix_key(listen)
                        data.get('data').append({
                            "{#POOLNAME}": "%s-%s" % (section, suffix) if suffix != '' else section,
                            "{#SOCKET}":   listen,
                        })
                    else:
                      continue

                except Exception as e:
                    self.logger.error(e)

                    continue

                except ConfigParser.NoOptionError as e:
                    continue

                if suffix:
                    self.logger.debug('Added POOLNAME: %s-%s' % (section, suffix))

        self.logger.debug('Discovered: %s' % (data))

        return data

    def run(self):
        if self.opts.verbose:
            log_handler = logging.StreamHandler(sys.stderr)
        else:
            log_handler = logging.handlers.SysLogHandler('/dev/log')
            formatter = logging.Formatter(fmt="zabbix-phpfpm-stats[%(process)d]: %(message)s")
            log_handler.setFormatter(formatter)

        if self.opts.debug:
            self.logger = self.set_log_level('debug')
        else:
          self.logger = self.set_log_level('info')

        self.logger.addHandler(log_handler)

        if self.opts.discover:
            data = self.autodiscover()
            print(json.dumps(data))

        else:
            try:
                fcgi_client = FCGIStatusClient(logger=self.logger, socket_path=self.opts.socket_path,
                                               status_path=self.opts.status_path)

                fcgi_client.make_request()
                status = fcgi_client.get_status()
                payload = self.get_payload(status)

                ret = self.zabbix_sender(payload=payload, zabbixserver=self.opts.zabbixserver,
                                         zabbixport=self.opts.zabbixport, senderloc=self.opts.senderloc,
                                         agentconfig=self.opts.agentconfig)

                print(ret)

            except Exception as e:
                self.logger.error(e)

                print(2)

                sys.exit(2)


if __name__ == '__main__':
    app = ZabbixPHPFPM()
    app.run()

# vim: set expandtab tabstop=2 shiftwidth=2:
