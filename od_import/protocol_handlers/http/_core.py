import io
import sys
import ssl
import json
import time
import logging
import zipfile
import tarfile
import operator
import platform
from base64 import b64decode
from html.parser import HTMLParser

from urllib.request import (
    urlopen,
    Request,
    HTTPHandler,
    HTTPSHandler,
    ProxyHandler,
    build_opener,
    quote
)

from urllib.error import (
    HTTPError,
    URLError
)

from urllib.parse import (
    urlencode,
    quote_plus
)

def request(url: str,  config: object, method: str=None, data: dict={}) -> object:
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
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
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
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    if not method:
        resp = opener(url)
    elif method in ["PUT", "POST"]:
        req = Request(url, method=method)
        encoded_data = urlencode(data).encode('utf-8')
        resp = opener(req, encoded_data)
    return resp
