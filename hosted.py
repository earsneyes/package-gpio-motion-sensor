#
# Part of info-beamer hosted. You can find the latest version
# of this file at:
# 
# https://github.com/info-beamer/package-sdk
#
# Copyright (c) 2014,2015,2016,2017,2018 Florian Wesch <fw@info-beamer.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the
#     distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

VERSION = "1.2"

import os
import sys
import json
import time
import errno
import socket
import select
import pyinotify
import thread
import threading
import requests
import re
from tempfile import NamedTemporaryFile

types = {}

def init_types():
    def type(fn):
        types[fn.__name__] = fn
        return fn

    @type
    def color(value):
        return value

    @type
    def string(value):
        return value

    @type
    def text(value):
        return value

    @type
    def section(value):
        return value

    @type
    def boolean(value):
        return value

    @type
    def select(value):
        return value

    @type
    def duration(value):
        return value

    @type
    def integer(value):
        return value

    @type
    def float(value):
        return value

    @type
    def font(value):
        return value

    @type
    def device(value):
        return value

    @type
    def resource(value):
        return value

    @type
    def json(value):
        return value

    @type
    def custom(value):
        return value

    @type
    def date(value):
        return value

init_types()

def log(msg):
    print >>sys.stderr, "[hosted.py] %s" % msg

def abort_service(reason):
    log("restarting service (%s)" % reason)
    try:
        thread.interrupt_main()
    except:
        pass
    time.sleep(2)
    os.kill(os.getpid(), 2)
    time.sleep(2)
    os.kill(os.getpid(), 15)
    time.sleep(2)
    os.kill(os.getpid(), 9)
    time.sleep(100)

class Configuration(object):
    def __init__(self):
        self._restart = False
        self._options = []
        self._config = {}
        self._parsed = {}
        self.parse_node_json(do_update=False)
        self.parse_config_json()

    def restart_on_update(self):
        log("going to restart when config is updated")
        self._restart = True

    def parse_node_json(self, do_update=True):
        with open("node.json") as f:
            self._options = json.load(f)['options']
        if do_update:
            self.update_config()

    def parse_config_json(self, do_update=True):
        with open("config.json") as f:
            self._config = json.load(f)
        if do_update:
            self.update_config()

    def update_config(self):
        if self._restart:
            return abort_service("restart_on_update set")

        def parse_recursive(options, config, target):
            # print 'parsing', config
            for option in options:
                if not 'name' in option:
                    continue
                if option['type'] == 'list':
                    items = []
                    for item in config[option['name']]:
                        parsed = {}
                        parse_recursive(option['items'], item, parsed)
                        items.append(parsed)
                    target[option['name']] = items
                    continue
                target[option['name']] = types[option['type']](config[option['name']])

        parsed = {}
        parse_recursive(self._options, self._config, parsed)
        log("updated config")
        self._parsed = parsed

    @property
    def raw(self):
        return self._config

    @property
    def metadata(self):
        return self._config['__metadata']

    def __getitem__(self, key):
        return self._parsed[key]

    def __getattr__(self, key):
        return self._parsed[key]

def setup_inotify(configuration):
    class EventHandler(pyinotify.ProcessEvent):
        def process_default(self, event):
            basename = os.path.basename(event.pathname)
            if basename == 'node.json':
                log("node.json changed")
                configuration.parse_node_json()
            elif basename == 'config.json':
                log("config.json changed!")
                configuration.parse_config_json()
            elif basename.endswith('.py'):
                abort_service("python file changed")

    wm = pyinotify.WatchManager()

    notifier = pyinotify.ThreadedNotifier(wm, EventHandler())
    notifier.daemon = True
    notifier.start()

    wm.add_watch('.', pyinotify.IN_MOVED_TO)

class Node(object):
    def __init__(self, node):
        self._node = node
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_raw(self, raw):
        log("sending %r" % (raw,))
        self._sock.sendto(raw, ('127.0.0.1', 4444))

    def send(self, data):
        self.send_raw(self._node + data)

    @property
    def is_top_level(self):
        return self._node == "root"

    @property
    def path(self):
        return self._node

    def write_file(self, filename, content):
        f = NamedTemporaryFile(prefix='.hosted-py-tmp', dir=os.getcwd())
        try:
            f.write(content)
        except:
            traceback.print_exc()
            f.close()
            raise
        else:
            f.delete = False
            f.close()
            os.rename(f.name, filename)

    def write_json(self, filename, data):
        self.write_file(json.dumps(
            data,
            ensure_ascii=False,
            separators=(',',':'),
        ).encode('utf8'))

    class Sender(object):
        def __init__(self, node, path):
            self._node = node
            self._path = path

        def __call__(self, data):
            if isinstance(data, (dict, list)):
                raw = "%s:%s" % (self._path, json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(',',':'),
                ).encode('utf8'))
            else:
                raw = "%s:%s" % (self._path, data)
            self._node.send_raw(raw)

    def __getitem__(self, path):
        return self.Sender(self, self._node + path)

    def __call__(self, data):
        return self.Sender(self, self._node)(data)

    def scratch_cached(self, filename, generator):
        cached = os.path.join(os.environ['SCRATCH'], filename)

        if not os.path.exists(cached):
            f = NamedTemporaryFile(prefix='scratch-cached-tmp', dir=os.environ['SCRATCH'])
            try:
                generator(f)
            except:
                raise
            else:
                f.delete = False
                f.close()
                os.rename(f.name, cached)

        if os.path.exists(filename):
            try:
                os.unlink(filename)
            except:
                pass
        os.symlink(cached, filename)

class APIError(Exception):
    pass

class APIProxy(object):
    def __init__(self, apis, api_name):
        self._apis = apis
        self._api_name = api_name

    @property
    def url(self):
        index = self._apis.get_api_index()
        if not self._api_name in index:
            raise APIError("api '%s' not available" % (self._api_name,))
        return index[self._api_name]['url']

    def unwrap(self, r):
        r.raise_for_status()
        resp = r.json()
        if not resp['ok']:
            raise APIError(u"api call failed: %s" % (
                resp.get('error', '<unknown error>'),
            ))
        return resp.get(self._api_name)

    def add_defaults(self, kwargs):
        if not 'timeout' in kwargs:
            kwargs['timeout'] = 10

    def get(self, **kwargs):
        self.add_defaults(kwargs)
        try:
            return self.unwrap(self._apis.session.get(
                url = self.url,
                **kwargs
            ))
        except APIError:
            raise
        except Exception as err:
            raise APIError(err)

    def post(self, **kwargs):
        self.add_defaults(kwargs)
        try:
            return self.unwrap(self._apis.session.post(
                url = self.url(),
                **kwargs
            ))
        except APIError:
            raise
        except Exception as err:
            raise APIError(err)

class APIs(object):
    def __init__(self, config):
        self._config = config
        self._index = None
        self._valid_until = 0
        self._lock = threading.Lock()
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'hosted.py version/%s' % (VERSION,)
        })

    def update_apis(self):
        log("fetching api index")
        r = self._session.get(
            url = self._config.metadata['api'],
            timeout = 5,
        )
        r.raise_for_status()
        resp = r.json()
        if not resp['ok']:
            raise APIError("cannot retrieve api index")
        self._index = resp['apis']
        self._valid_until = resp['valid_until'] - 300

    def get_api_index(self):
        with self._lock:
            now = time.time()
            if now > self._valid_until:
                self.update_apis()
            return self._index

    @property
    def session(self):
        return self._session

    def list(self):
        try:
            index = self.get_api_index()
            return sorted(index.keys())
        except Exception as err:
            raise APIError(err)

    def __getitem__(self, api_name):
        return APIProxy(self, api_name)

    def __getattr__(self, api_name):
        return APIProxy(self, api_name)

class GPIOMonitor(object):
    def __init__(self):
        self._pin_fd = {}
        self._state = {}
        self._fd_2_pin = {}
        self._poll = select.poll()
        self._lock = threading.Lock()

    def monitor(self, pin, invert=False):
        if pin not in self._pin_fd:
            if not os.path.exists("/sys/class/gpio/gpio%d" % pin):
                with open("/sys/class/gpio/export", "wb") as f:
                    f.write(str(pin))
            # mdev is giving the newly create GPIO directory correct permissions.
            for i in range(10):
                try:
                    with open("/sys/class/gpio/gpio%d/active_low" % pin, "wb") as f:
                        f.write("1" if invert else "0")
                    break
                except IOError as err:
                    if err.errno != errno.EACCES:
                        raise
                time.sleep(0.1)
                log("waiting for GPIO permissions")
            else:
                raise IOError(errno.EACCES, "Cannot access GPIO")
            with open("/sys/class/gpio/gpio%d/direction" % pin, "wb") as f:
                f.write("in")
            with open("/sys/class/gpio/gpio%d/edge" % pin, "wb") as f:
                f.write("both")
            fd = os.open("/sys/class/gpio/gpio%d/value" % pin, os.O_RDONLY)
            self._state[pin] = bool(int(os.read(fd, 5)))
            self._fd_2_pin[fd] = pin
            self._pin_fd[pin] = fd
            self._poll.register(fd, select.POLLPRI | select.POLLERR)

    def poll(self, timeout=1000):
        changes = []
        for fd, evt in self._poll.poll(timeout):
            os.lseek(fd, 0, 0)
            state = bool(int(os.read(fd, 5)))
            pin = self._fd_2_pin[fd]
            with self._lock:
                prev_state, self._state[pin] = self._state[pin], state
            if state != prev_state:
                changes.append((pin, state))
        return changes

    def poll_forever(self):
        while 1:
            for event in self.poll():
                yield event

    def on(self, pin):
        with self._lock:
            return self._state.get(pin, False)

class Device(object):
    def __init__(self):
        self._socket = None
        self._gpio = GPIOMonitor()

    @property
    def gpio(self):
        return self._gpio

    def ensure_connected(self):
        if self._socket:
            return True
        try:
            log("establishing upstream connection")
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.connect(os.getenv('SYNCER_SOCKET', "/tmp/syncer"))
            return True
        except Exception as err:
            log("cannot connect to upstream socket: %s" % (err,))
            return False

    def send_raw(self, raw):
        try:
            if self.ensure_connected():
                self._socket.send(raw + '\n')
        except Exception as err:
            log("cannot send to upstream: %s" % (err,))
            if self._socket:
                self._socket.close()
            self._socket = None

    def send_upstream(self, **data):
        self.send_raw(json.dumps(data))

    def turn_screen_off(self):
        self.send_raw("tv off")

    def turn_screen_on(self):
        self.send_raw("tv on")

    def screen(self, on=True):
        if on:
            self.turn_screen_on()
        else:
            self.turn_screen_off()

    def reboot(self):
        self.send_raw("reboot")

    def restart_infobeamer(self):
        self.send_raw("infobeamer restart")

    def verify_cache(self):
        self.send_raw("syncer verify_cache")

if __name__ == "__main__":
    device = Device()
    while 1:
        try:
            command = raw_input("syncer> ")
            device.send_raw(command)
        except (KeyboardInterrupt, EOFError):
            break
        except:
            import traceback
            traceback.print_exc()
else:
    log("starting version %s" % (VERSION,))
    node = NODE = Node(os.environ['NODE'])
    device = DEVICE = Device()
    config = CONFIG = Configuration()
    api = API = APIs(CONFIG)
    setup_inotify(CONFIG)
    log("ready to go!")


if sys.version_info > (3,):
    long = int

BASE_URL = 'http://things.ubidots.com/api/v1.6/'


def get_response_json_or_info_message(response):
    if response.status_code == 204:
        resp = {"detail": "this response don't need a body"}

    try:
        resp = response.json()
    except Exception:
        resp = {"detail": "this response doesn't have a valid json response"}
    return resp


class UbidotsError(Exception):
    pass


class UbidotsHTTPError(UbidotsError):
    def __init__(self, *args, **kwargs):
        self.response = kwargs['response']
        self.detail = get_response_json_or_info_message(self.response)
        self.status_code = self.response.status_code
        del kwargs['response']
        super(UbidotsHTTPError, self).__init__(*args, **kwargs)


class UbidotsError400(UbidotsHTTPError):
    """Exception thrown when server returns status code 400 Bad request"""
    pass


class UbidotsError404(UbidotsHTTPError):
    """Exception thrown when server returns status code 404 Not found"""
    pass


class UbidotsError500(UbidotsHTTPError):
    """Exception thrown when server returns status code 500"""
    pass


class UbidotsForbiddenError(UbidotsHTTPError):
    """Exception thrown when server returns status code 401 or 403"""
    pass


class UbidotsBulkOperationError(UbidotsHTTPError):
    '''
    TODO: the 'status_code' for this exception is 200!!
    '''
    pass


class UbidotsInvalidInputError(UbidotsError):
    """Exception thrown when client-side verification fails"""
    pass


def create_exception_object(response):
    """Creates an Exception object for an erronous status code."""

    code = response.status_code

    if code == 500:
        return UbidotsError500("An Internal Server Error Occurred.", response=response)
    elif code == 400:
        return UbidotsError400("Your response is invalid", response=response)
    elif code == 404:
        return UbidotsError404("Resource responseed not found:\n  ", response=response)
    elif code in [403, 401]:
        return UbidotsForbiddenError(
            "Your token is invalid or you don't have permissions to access this resource:\n ",
            response=response
        )
    else:
        return UbidotsError("Not Handled Exception: ", response=response)


def raise_informative_exception(list_of_error_codes):
    def real_decorator(fn):
        def wrapped_f(self, *args, **kwargs):
            response = fn(self, *args, **kwargs)
            if response.status_code in list_of_error_codes:
                try:
                    body = response.text
                except:
                    body = ""

                # error = create_exception_object(response.status_code, body)
                error = create_exception_object(response)
                raise error
            else:
                return response
        return wrapped_f
    return real_decorator


def try_again(list_of_error_codes, number_of_tries=2):
    def real_decorator(fn):
        def wrapped_f(self, *args, **kwargs):
            for i in range(number_of_tries):
                response = fn(self, *args, **kwargs)
                if response.status_code not in list_of_error_codes:
                    return response
                else:
                    self.initialize()

            try:
                body = response.text
            except:
                body = ""

            error = create_exception_object(response)
            raise error

        return wrapped_f
    return real_decorator


def validate_input(type, required_keys=[]):
    '''
    Decorator for validating input on the client side.
    If validation fails, UbidotsInvalidInputError is raised and the function
    is not called.
    '''
    def real_decorator(fn):
        def wrapped_f(self, *args, **kwargs):
            if not isinstance(args[0], type):
                raise UbidotsInvalidInputError("Invalid argument type. Required: " + str(type))

            def check_keys(obj):
                for key in required_keys:
                    if key not in obj:
                        raise UbidotsInvalidInputError('Key "%s" is missing' % key)

            if isinstance(args[0], list):
                list(map(check_keys, args[0]))
            elif isinstance(args[0], dict):
                check_keys(args[0])

            return fn(self, *args, **kwargs)
        return wrapped_f
    return real_decorator


class ServerBridge(object):
    '''
    Responsabilites: Make petitions to the browser with the right headers and arguments
    '''

    def __init__(self, apikey=None, token=None, base_url=None):
        self.base_url = base_url or BASE_URL
        if apikey:
            self._token = None
            self._apikey = apikey
            self._apikey_header = {'X-UBIDOTS-APIKEY': self._apikey}
            self.initialize()
        elif token:
            self._apikey = None
            self._token = token
            self._set_token_header()

    def _get_token(self):
        self._token = self._post_with_apikey('auth/token').json()['token']
        self._set_token_header()

    def _set_token_header(self):
        self._token_header = {'X-AUTH-TOKEN': self._token}

    def initialize(self):
        if self._apikey:
            self._get_token()

    @raise_informative_exception([400, 404, 500, 401, 403])
    def _post_with_apikey(self, path):
        headers = self._prepare_headers(self._apikey_header)
        response = requests.post(self.base_url + path, headers=headers)
        return response

    @try_again([403, 401])
    @raise_informative_exception([400, 404, 500])
    def get(self, path, **kwargs):
        headers = self._prepare_headers(self._token_header)
        response = requests.get(self.base_url + path, headers=headers, **kwargs)
        return response

    def get_with_url(self, url, **kwargs):
        headers = self._prepare_headers(self._token_header)
        response = requests.get(url, headers=headers, **kwargs)
        return response

    @try_again([403, 401])
    @raise_informative_exception([400, 404, 500])
    def post(self, path, data, **kwargs):
        headers = self._prepare_headers(self._token_header)
        data = self._prepare_data(data)
        response = requests.post(self.base_url + path, data=data, headers=headers, **kwargs)
        return response

    @try_again([403, 401])
    @raise_informative_exception([400, 404, 500])
    def delete(self, path, **kwargs):
        headers = self._prepare_headers(self._token_header)
        response = requests.delete(self.base_url + path, headers=headers, **kwargs)
        return response

    def _prepare_headers(self, *args, **kwargs):
        headers = self._transform_a_list_of_dictionaries_to_a_dictionary(args)
        headers.update(self._get_custom_headers())
        headers.update(kwargs.items())
        return headers

    def _prepare_data(self, data):
        return json.dumps(data)

    def _get_custom_headers(self):
        headers = {'content-type': 'application/json'}
        return headers

    def _transform_a_list_of_dictionaries_to_a_dictionary(self, list_of_dicts):
        headers = {}
        for dictionary in list_of_dicts:
            for key, val in dictionary.items():
                headers[key] = val
        return headers


class ApiObject(object):

    def __init__(self, raw_data, bridge, *args, **kwargs):
        self.raw = raw_data
        self.api = kwargs.get('api', None)
        self.bridge = bridge
        self._from_raw_to_attributes()

    def _from_raw_to_attributes(self):
        for key, value in self.raw.items():
            setattr(self, key, value)


def transform_to_datasource_objects(raw_datasources, bridge):
    datasources = []
    for ds in raw_datasources:
        datasources.append(Datasource(ds, bridge))
    return datasources


def transform_to_variable_objects(raw_variables, bridge):
    variables = []
    for variable in raw_variables:
        variables.append(Variable(variable, bridge))
    return variables


class Datasource(ApiObject):

    def remove_datasource(self):
        return self.bridge.delete('datasources/' + self.id) == 204

    def get_variables(self, numofvars="ALL"):
        endpoint = 'datasources/' + self.id + '/variables'
        response = self.bridge.get(endpoint)
        pag = self.get_new_paginator(self.bridge, response.json(), transform_to_variable_objects, endpoint)
        return InfoList(pag, numofvars)

    def get_new_paginator(self, bridge, json_data, transform_function, endpoint):
        return Paginator(bridge, json_data, transform_function, endpoint)

    @validate_input(dict, ["name", "unit"])
    def create_variable(self, data):
        response = self.bridge.post('datasources/' + self.id + '/variables', data)
        return Variable(response.json(), self.bridge, datasource=self)

    def __repr__(self):
        return self.name


class Variable(ApiObject):

    def __init__(self, raw_data, bridge, *args, **kwargs):
        super(Variable, self).__init__(raw_data, bridge, *args, **kwargs)

    def get_values(self, numofvals="ALL"):
        endpoint = 'variables/' + self.id + '/values'
        response = self.bridge.get(endpoint).json()
        pag = Paginator(self.bridge, response, self.get_transform_function(), endpoint)
        return InfoList(pag, numofvals)

    def get_transform_function(self):
        def transform_function(values, bridge):
            return values
        return transform_function

    @validate_input(dict, ["value"])
    def save_value(self, data):
        if not isinstance(data.get('timestamp', 0), (int, long)):
            raise UbidotsInvalidInputError('Key "timestamp" must point to an int value.')

        return self.bridge.post('variables/' + self.id + '/values', data).json()

    @validate_input(list, ["value", "timestamp"])
    def save_values(self, data, force=False):
        if not all(isinstance(e['timestamp'], (int, long)) for e in data):
            raise UbidotsInvalidInputError('Key "timestamp" must point to an int value.')

        path = 'variables/' + self.id + '/values'
        path += ('', '?force=true')[int(force)]
        response = self.bridge.post(path, data)
        data = response.json()
        if not self._all_values_where_accepted(data):
            raise UbidotsBulkOperationError("There was a problem with some of your posted values.", response=response)
        return data

    def _all_values_where_accepted(self, data):
        return all(map(lambda x: x['status_code'] == 201, data))

    def remove_variable(self):
        return self.bridge.delete('variables/' + self.id).status_code == 204

    def remove_values(self, t_start, t_end):
        return self.bridge.delete('variables/{0}/values/{1}/{2}'.format(self.id, t_start, t_end))

    def remove_all_values(self):
        from time import time
        t_start = 0
        t_end = int(time()) * 1000
        return self.remove_values(t_start=t_start, t_end=t_end)

    def get_datasource(self, **kwargs):
        if not self._datasource:
            api = ApiClient(server_bridge=self.bridge)
            self._datasource = api.get_datasource(url=self.datasource['url'])
        return self._datasource

    def __repr__(self):
        return self.name


class Paginator(object):
    def __init__(self, bridge, response, transform_function, endpoint):
        self.bridge = bridge
        self.response = response
        self.endpoint = endpoint
        self.hasNext = self.response['next']
        self.transform_function = transform_function
        self.items_per_page = self._get_number_of_items_per_page()
        self.items = []
        self.actualPage = 1
        self.add_new_items(response)

    def _there_is_more_than_one_page(self):
        return self.hasNext

    def _get_number_of_items_per_page(self):
        return len(self.response['results'])

    def add_new_items(self, response):
        self.hasNext = response['next']
        new_items = self.transform_function(response['results'], self.bridge)
        self.items = self.items + new_items
        self.actualPage = self.actualPage + 1

    def get_page(self):
        try:
            response = self.bridge.get("{0}?page={1}".format(self.endpoint, self.actualPage)).json()
        except JSONDecodeError:
            # When the server returns something that is not JSON decodable
            # this will crash.
            raise UbidotsHTTPError("Invalid response from the server")
        self.add_new_items(response)
        return self.items

    def get_all_items(self):
        self.get_pages()
        return self.items

    def get_pages(self):
        while self.hasNext is not None:
            self.get_page()

    def _filter_valid_pages(self, list_of_pages):
        return list(set(list_of_pages) & set(self.pages))

    def _add_items_to_results(self, raw_results):
        self.result[self.current_page] = raw_results

    def _flat_items(self, pages):
        nestedlist = [value for key, value in self.items.items() if key in pages]
        return [item for sublist in nestedlist for item in sublist]


class InfoList(list):
    def __init__(self, paginator, numofitems='ALL'):
        self.paginator = paginator
        items = self.get_items(numofitems)
        super(InfoList, self).__init__(items)

    def get_items(self, numofitems):
        return self.paginator.get_all_items()


class ApiClient(object):
    bridge_class = ServerBridge

    def __init__(self, apikey=None, token=None, base_url=None, bridge=None):
        if bridge is None:
            self.bridge = ServerBridge(apikey, token, base_url)
        else:
            self.bridge = bridge

    def get_datasources(self, numofdsources='ALL', **kwargs):
        endpoint = 'datasources'
        response = self.bridge.get(endpoint, **kwargs).json()
        pag = Paginator(self.bridge, response, transform_to_datasource_objects, endpoint)
        return InfoList(pag, numofdsources)

    def get_datasource(self, ds_id=None, url=None, **kwargs):
        if not id and not url:
            raise UbidotsInvalidInputError("id or url required")

        if ds_id:
            raw_datasource = self.bridge.get('datasources/' + str(ds_id), **kwargs).json()
        elif url:
            raw_datasource = self.bridge.get_with_url(url, **kwargs).json()

        return Datasource(raw_datasource, self.bridge)

    @validate_input(dict, ["name"])
    def create_datasource(self, data):
        raw_datasource = self.bridge.post('datasources/', data).json()
        return Datasource(raw_datasource, self.bridge)

    def get_variables(self, numofvars='ALL', **kwargs):
        endpoint = 'variables'
        response = self.bridge.get('variables', **kwargs).json()
        pag = Paginator(self.bridge, response, transform_to_variable_objects, endpoint)
        return InfoList(pag, numofvars)

    def get_variable(self, var_id, **kwargs):
        raw_variable = self.bridge.get('variables/' + str(var_id), **kwargs).json()
        return Variable(raw_variable, self.bridge)

    @validate_input(list, ["variable", "value"])
    def save_collection(self, data, force=False):
        path = "collections/values"
        path += ('', '?force=true')[int(force)]
        response = self.bridge.post(path, data)
        data = response.json()
        if not self._all_collection_items_where_accepted(data):
            raise UbidotsBulkOperationError(
                "There was a problem with some of your posted items values.",
                response=response
            )
        return data

    def _all_collection_items_where_accepted(self, data):
        return all(map(lambda x: x['status_code'] == 201, data))
