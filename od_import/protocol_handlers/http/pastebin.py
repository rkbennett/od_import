import io
import sys
import ssl
import json
import time
import logging
import operator
import platform
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

from urllib.parse import urlencode

########################## Protocol Handlers #########################

def pastebin(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
    """
    Description:
        Handles http/s requests for content
    Args:
        url: url to connect to for packages
        path: subpath to subpackage or nested module
        path_cache: list of paths the import hook tracks
        cache_update: informs the module if the import hooks path cache should be updated with this interation
        config: configuration options for the import hook's protocol handler (this module)
    return:
        bytes of file content or empty bytes object
    """
    if 'module' not in config.__dict__:
        raise KeyError("Missing required key 'module'...")
    if 'paste_key' not in config.__dict__:
        raise KeyError("Missing required key 'paste_key'...")
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if 'verify' not in config.__dict__:
        config.verify = True
    if 'ca_file' not in config.__dict__:
        config.ca_file = None
    if 'ca_data' not in config.__dict__:
        config.ca_data = None
    if 'visibility' not in config.__dict__ or config.visibility not in ["public", "private", "unlisted", "burn", "passworded"]:
        config.visibility == 'public'
    if config.visibility in ['private', 'burn', 'passworded']:
        if 'developer_key' not in config.__dict__:
            raise KeyError(f"Missing required key 'developer_key' when visibility set to '{config.visibility}'...")
        if 'user_key' not in config.__dict__:
            raise KeyError(f"Missing required key 'user_key' when visibility set to '{config.visibility}'...")
        if config.visibility == 'passworded':
            if 'paste_password' not in config.__dict__:
                raise KeyError(f"Missing required key 'paste_password' when visibility set to '{config.visibility}'...")
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
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    url = "/".join(url.split("/")[:3])
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    logging.warn(url)
    if config.visibility in ["public", "unlisted"]:
        url = f"{url}/raw/{config.paste_key}"
        resp = opener(url).read()
    elif config.visibility == "private":
        url = f"{url}/api/api_raw.php"
        req = Request(url, method='POST')
        data = {
            "api_dev_key": config.developer_key,
            "api_user_key": config.user_key,
            "api_option": "show_paste",
            "api_paste_key": config.paste_key
        }
        if config.visibility == "passworded":
            data['paste_password'] = config.paste_password
        encoded_data = urlencode(data).encode('utf-8')
        resp = opener(req, encoded_data).read()
    if resp:
        if f"{config.module}.py" not in path_cache:
            path_cache += [f"{config.module.replace('.', '/')}.py"]
    return resp
