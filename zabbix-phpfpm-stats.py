#!/usr/bin/env python2

import sys, socket, struct, stat, os, json, glob
import logging, logging.handlers

import ConfigParser

from subprocess import Popen, PIPE
from argparse import ArgumentParser as Parser

class FCGIStatusClient():
  # FCGI protocol version
  FCGI_VERSION = 1

  # FCGI record types
  FCGI_BEGIN_REQUEST = 1
  FCGI_PARAMS = 4

  # FCGI roles
  FCGI_RESPONDER = 1

  # FCGI header length
  FCGI_HEADER_LENGTH = 8

  def __init__(self, logger = None, socket_path = "unix:///run/php/php7.0-fpm.sock", socket_timeout = 5.0, status_path = "/fpm-status" ):
    self.logger = logger

    if socket_path.startswith('tcp://'):
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif socket_path.startswith('unix://'):
      self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
      raise Exception('Unknown socket address: %s' % socket_path)

    self.socket_path = socket_path
    self.status_path = status_path
    self.set_socket_timeout(socket_timeout)
    self.request_id = 1

    self.params = {
      "SCRIPT_NAME": status_path,
      "SCRIPT_FILENAME": status_path,
      "QUERY_STRING": "json",
      "REQUEST_METHOD": "GET",
    }

  def set_socket_timeout(self, timeout):
    self.socket_timeout = timeout
    self.socket.settimeout(self.socket_timeout)

  def connect(self):
    try:
      if self.socket_path.startswith('tcp://'):
        host, _, port = self.socket_path[len('tcp://'):].partition(':')
        self.socket.connect((host, int(port)))
      elif self.socket_path.startswith('unix://'):
        self.socket.connect(self.socket_path[len('unix://'):])
      else:
        sys.exit(1)
    except Exception as e:
      self.logger.error("Can not connect to socket: %s" % (self.socket_path))
      sys.exit(2)

  def close(self):
    self.socket.close()

  def define_begin_request(self):
    fcgi_begin_request = struct.pack("!HB5x", self.FCGI_RESPONDER, 0)
    fcgi_header        = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_BEGIN_REQUEST, self.request_id, len(fcgi_begin_request), 0)
    self.fcgi_begin_request = fcgi_header + fcgi_begin_request

  def define_parameters(self):
    parameters = []
    for name, value in self.params.items():
      parameters.append(chr(len(name)) + chr(len(value)) + name + value)

    parameters             = ''.join(parameters)
    parameters_length      = len(parameters)
    parameters_padding_req = parameters_length & 7
    parameters_padding     = b'\x00' * parameters_padding_req

    fcgi_header_start = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_PARAMS, self.request_id, parameters_length , parameters_padding_req)
    fcgi_header_end   = struct.pack("!BBHHBx", self.FCGI_VERSION, self.FCGI_PARAMS, self.request_id, 0, 0)
    self.fcgi_params = fcgi_header_start  + parameters.encode() + parameters_padding + fcgi_header_end

  def execute(self):
    try:
      self.socket.send(self.fcgi_begin_request)
      self.socket.send(self.fcgi_params)

      header = self.socket.recv(self.FCGI_HEADER_LENGTH)
      fcgi_version, request_type, request_id, request_length, request_padding = struct.unpack("!BBHHBx", header)

      if request_type == 6:
        self.raw_status_data=self.socket.recv(request_length)
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
      'active_processes': dstatus.get('active processes'),
      'accepted_conn': dstatus.get('accepted conn'),
      'process_manager': dstatus.get('process manager'),
      'listen_queue': dstatus.get('listen queue'),
      'start_since': dstatus.get('start since'),
#      'idle_processes': dstatus.get('idle processes'),
      'start_time': dstatus.get('start time'),
      'slow_requests': dstatus.get('slow requests'),
      'max_active_processes': dstatus.get('max active processes'),
      'max_children_reached': dstatus.get('max children reached'),
      'max_listen_queue': dstatus.get('max listen queue'),
      'total_processes': dstatus.get('total processes'),
      'listen_queue_len': dstatus.get('listen queue len'),
      'pool': dstatus.get('pool'),
    }

    return status

class ZabbixPHPFPM():

  _opts = None

  searchable_paths = [
    '/etc/php*/fpm/php-fpm.d/*.conf',
    '/etc/php5.6/fpm/pool.d/*.conf',
    '/etc/php/*/fpm/pool/*.conf',
  ]

  @property
  def opts(self):
    if self._opts is None:
      parser = Parser(
        version = "%(prog)s version v0.3",
        prog = os.path.basename(__file__),
        description = """This program gathers data from PHP-FPM's
            built-in status page and sends it to
            Zabbix. The data is sent via zabbix_sender.
            License: GPLv2
        """,
      )

      parser.add_argument(
        "--dry-run",
        action = "store_true",
        dest = "dryrun",
        default = False,
        help = "Do not send data to zabbix"
      )

      parser.add_argument(
        "--discover",
        action = "store_true",
        dest = "discover",
        default = False,
        help = "Discover pools",
      )
      parser.add_argument(
        "-V",
        "--verbose",
        action = "store_true",
        dest = "verbose",
        default = False,
        help = "output verbosity",
      )

      parser.add_argument(
        "-D",
        "--debug",
        action = "store_true",
        dest = "debug",
        default = False,
        help = "print debug information. (default: %(default)s)",
      )

      parser.add_argument(
        "-s",
        "--sender",
        action = "store",
        dest = "senderloc",
        default = "/usr/bin/zabbix_sender",
        help = "location to the zabbix_sender executable. (default: %(default)s)",
      )
      parser.add_argument(
        "-z",
        "--zabbixserver",
        action = "store",
        dest = "zabbixserver",
        default = "localhost",
        help = "zabbix trapper hostname",
      )
      parser.add_argument(
        "-q",
        "--zabbixport",
        action = "store",
        type = int,
        dest = "zabbixport",
        default = 10051,
        help = "zabbix port to connect to. (default: %(default)s)",
      )
      parser.add_argument(
        "-c",
        "--zabbixsource",
        action = "store",
        dest = "zabbixsource",
        default = "localhost",
        help = "zabbix host to use when sending values. (default: %(default)s)",
      )
      parser.add_argument(
        "--config",
        action = "store",
        dest = "agentconfig",
        default = None,
        help = "zabbix agent config to derive Hostname and ServerActive from. (default: %(default)s)",
      )

      # PHP-FPM specific
      parser.add_argument(
        "-S",
        "--socket",
        action = "append",
        dest = "socket",
        default = None,
        help = "Use socket (unix://, tcp://) (default: unix:///run/php/php7.0-fpm.sock",
      )
      parser.add_argument(
        "-P",
        "--path",
        action = "store",
        dest = "status_path",
        default = '/fpm-status',
        help = "Status path (default: %(default)s)",
      )

      self._opts = parser.parse_args()

      if self._opts.socket is None:
        self._opts.socket = ['unix:///run/php/php7.0-fpm.sock']

    return self._opts

  def zabbix_sender(self, payload, agentconfig = None, zabbixserver = None, zabbixport = 10051, senderloc = '/usr/bin/zabbix_sender' ):
    sender_command = []
    result = 0
    err = ''

    if not (os.path.exists(senderloc)) or not (os.access(senderloc, os.X_OK)):
      self.logger.error("%s not exists or not executable" %(senderloc))
      raise Exception("%s not exists or not executable" %(senderloc))

    else:
      if agentconfig is not None:
        self.logger.debug('sending to server in agent config %s' % agentconfig)
        sender_command = [ senderloc, '-vv', '--config', agentconfig, '--input-file', '-' ]
      else:
        if zabbixserver is not None:
          self.logger.debug('sending to server %s:%s' % (zabbixserver, zabbixport))
          sender_command = [ senderloc, '-vv', '--zabbix-server', zabbixserver, '--port', str(zabbixport), '--input-file', '-' ]
        else:
          self.logger.error('must specify agent configuration or server name to call zabbix_sender with')

      try:
        self.logger.debug('Payload:\n%s' % (payload))

        if self.opts.dryrun:
          ret = result = 0

          return 1

        p = Popen(sender_command, stdout = PIPE, stdin = PIPE, stderr = PIPE)
        out, err = p.communicate(input=payload)
        ret = p.wait()
        result = 1
      except Exception, e:
        err = "%s\nFailed to execute: '%s'" % (e, " ".join(sender_command))
      finally:
        if ret != 0:
          raise Exception("error returned from %s! ret: %d, out: '%s', err: '%s'" % (sender_command[0], ret, out.strip('\n'), err.strip('\n')))

    return result

  def setLogLevel(self, loglevel):
    """
        Setup logging.
        """

    numeric_loglevel = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
      raise ValueError('Invalid log level: "%s"\n Try: "debug", "info", "warning", "critical".' % loglevel)

    program = os.path.basename( __file__ )
    logger = logging.getLogger( program )
    logger.setLevel(numeric_loglevel)

    return logger

  def get_payload(self, status):
    pool = status.get('pool')
    payload = ''

    if self.opts.agentconfig:
      for item, value in status.items():
        payload += "-\tphp-fpm.%s[%s]\t%s\n" % (
          item,
          pool,
          value,
        )
    else:
      for item, value in status.items():
        payload += "%s php-fpm.%s[%s] %s\n" % (
          self.opts.zabbixsource,
          item,
          pool,
          value,
        )

    return payload

  def autodiscover(self):
    data = {
      'data': [],
    }

    for s in self.searchable_paths:
      config = ConfigParser.SafeConfigParser(allow_no_value=True)

      configs = glob.glob(s)

      for c in configs:
        config.read(c)

      for section in config.sections():
        try:
          status_path = config.get(section, 'pm.status_path')

          data.get('data').append({
              "{#POOLNAME}": section,
              "{#SOCKET}": config.get(section, 'listen'),
          })
        except ConfigParser.NoOptionError as e:
          continue

    return data

  def run(self):
    if self.opts.verbose:
      log_handler = logging.StreamHandler(sys.stderr)
    else:
      log_handler = logging.handlers.SysLogHandler('/dev/log')

    self.logger = self.setLogLevel('info')

    if self.opts.debug:
      self.logger = self.setLogLevel('debug')

    self.logger.addHandler(log_handler)

    if self.opts.discover:
      data = self.autodiscover()
      print(json.dumps(data))

      #data = self.autodiscover()
      #print(json.dumps(data))

    else:
      try:
        for s in self.opts.socket:
          fcgi_client = FCGIStatusClient(
            logger = self.logger,
            socket_path = s,
            status_path = self.opts.status_path,
          )
          fcgi_client.make_request()
          status = fcgi_client.get_status()
          payload = self.get_payload(status)

          self.zabbix_sender(
            payload=payload,
            zabbixserver=self.opts.zabbixserver,
            zabbixport=self.opts.zabbixport,
            senderloc=self.opts.senderloc,
            agentconfig=self.opts.agentconfig,
          )

      except Exception as e:
        self.logger.error(e)
        sys.exit(2)

if __name__ == '__main__':
  app = ZabbixPHPFPM()
  app.run()

# vim: set expandtab tabstop=2 shiftwidth=2:
