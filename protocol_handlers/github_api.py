import sys
import ssl
import json
import logging
from base64 import b64decode
from html.parser import HTMLParser

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

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

########################## Protocol Handlers #########################

def github_api(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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

    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    elif 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if 'branch' not in config.__dict__:
        config.branch = "main"
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
    else:
        req_handler = ProxyHandler({})
    if config.api_key:
        config.headers["Authorization"] =f"Bearer {config.api_key}"
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    if path:
        url = "/".join([url, path])
    url_list = url.split("://")
    path_list = url_list[1].split("/")
    path_list.insert(0, "repos")
    path_list.insert(3, "contents")
    if len(path_list) == 4:
        path_list.append("")
    url = f"""https://api.github.com/{"/".join(path_list)}"""
    opener = req_opener.open
    resp = opener(url).read()
    resp_json = json.loads(resp)
    if isinstance(resp_json, dict):
        resp = b64decode(resp_json['content'].encode())
    if cache_update:
        try:
            # attempt to parse links on the page
            repo_files = [item['path'] if item['type'] == "file" else f"{item['path']}/" for item in json.loads(resp)]
            path_cache += repo_files
        except Exception as e:
            # do some logging
            logging.info(e)
            pass
    return resp
