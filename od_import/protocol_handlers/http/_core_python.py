import ssl
import copy
import json
import logging
import http.client

from urllib.request import (
    Request,
    HTTPHandler,
    HTTPSHandler,
    ProxyHandler,
    build_opener,
    quote
)

from urllib.parse import (
    urlencode
)

def request(url: str,  config: object, method: str=None, data: dict={}, urlencoded: bool=False, **extra_args) -> object:
    """
    Description:
        Handles common http/s requests for content
    Args:
        url: url to connect to for packages
        config: configuration options for the import hook's protocol handler
        method: string of desired method to use (GET, PUT, POST)
        data: dictionary of data to pass with POST or PUT methods  
    return:
        An build_opener.open object
    """
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    elif 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'verify' not in config.__dict__:
        config.verify = True
    if 'ca_file' not in config.__dict__:
        config.ca_file = None
    if 'ca_data' not in config.__dict__:
        config.ca_data = None
    if 'username' not in config.__dict__:
        config.username = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'timeout' not in config.__dict__ or not (isinstance(config.timeout, int) or isinstance(config.timeout, float)):
        config.timeout = None
    if 'http_version' in config.__dict__ and config.http_version in ['1.0', '1.1']:
        set_http_version = True
        default_http_vsn = http.client.HTTPConnection._http_vsn
        default_http_vsn_str = http.client.HTTPConnection._http_vsn_str
        http.client.HTTPConnection._http_vsn = int(config.http_version.replace('.',''))
        http.client.HTTPConnection._http_vsn_str = f"HTTP/{config.http_version}"
    else:
        set_http_version = False
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler(
            {
                "http": config.proxy['url'],
                "https": config.proxy['url']
            }
        )
    elif url.startswith("https://"):
        if not config.verify:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif config.ca_file or config.ca_data:
            ssl_context = ssl.create_default_context(cafile=config.ca_file, cadata=config.ca_data)
        else:
            ssl_context = None
        req_handler = HTTPSHandler(context=ssl_context)
    else:
        req_handler = HTTPHandler()
    headers = copy.deepcopy(config.headers)
    req_opener = build_opener(req_handler)
    if 'temp_headers' in extra_args:
        headers.update(extra_args['temp_headers'])
    if headers:
        req_opener.addheaders = [(header, value) for header, value in headers.items()]
    opener = req_opener.open
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    try:
        if not method or method == "GET":
            resp = opener(url, timeout=config.timeout)
        elif method in ["PUT", "POST"]:
            req = Request(url, method=method, headers=headers)
            if urlencoded:
                encoded_data = urlencode(data).encode('utf-8')
            else:
                encoded_data = json.dumps(data).encode()
            resp = opener(req, encoded_data, timeout=config.timeout)
        return resp
    except Exception as e:
        logging.warning(f"Encountered error during request: {e}")
        raise e
    finally:
        if set_http_version:
            http.client.HTTPConnection._http_vsn = default_http_vsn
            http.client.HTTPConnection._http_vsn_str = default_http_vsn_str

