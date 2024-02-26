import copy
import json
import logging
from urllib.request import quote
from .windows.winhttp import Request, opener
from urllib.parse import urlencode

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
        config.headers = {}
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
    if 'http_version' not in config.__dict__ or config.http_version not in ['1.0', '1.1']:
        config.http_version = None
    headers = copy.deepcopy(config.headers)
    if 'temp_headers' in extra_args:
        headers.update(extra_args['temp_headers'])
    if 'user-agent' in headers:
        userAgent = headers.pop('User-agent')
    else:
        userAgent = None
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    try:
        if not method or method == "GET":
            req = Request(url, userAgent=userAgent, http_version=config.http_version, method="GET", headers=headers)
            resp = opener(req, timeout=config.timeout)
        elif method in ["PUT", "POST"]:
            req = Request(url, userAgent=userAgent, http_version=config.http_version, method=method, headers=headers)
            if urlencoded:
                encoded_data = urlencode(data).encode('utf-8')
            else:
                encoded_data = json.dumps(data).encode()
            resp = opener(req, data=encoded_data, timeout=config.timeout, verify=config.verify)
        return resp
    except Exception as e:
        logging.warning(f"Encountered error during request: {e}")
        raise e