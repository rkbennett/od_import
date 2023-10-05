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

from urllib.parse import urlencode

########################## Protocol Handlers #########################

def git_api(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'git' not in config.__dict__:
        raise KeyError("Missing required key 'git'...")
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if config.git == "github":
        if 'user' not in config.__dict__:
            raise KeyError("Missing required key 'user' when git type is 'github'")
        if 'repo' not in config.__dict__:
            raise KeyError("Missing required key 'repo' when git type is 'github'...")
        if config.api_key:
            config.headers["Authorization"] =f"Bearer {config.api_key}"
    if config.git == "gitlab":
        if ()'group' not in config.__dict__ or 'project' not in config.__dict__) and 'project_id' not in config.__dict__:
            raise KeyError("Missing required key(s) 'group' and 'project' required when git type is 'gitlab' and 'project_id' key not set...")
        if config.api_key:
            config.headers["PRIVATE-TOKEN"] =f"{config.api_key}"
        if 'project_id' not in config.__dict__:
            config.project_id = None
    if 'branch' not in config.__dict__:
        config.branch = None
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
    else:
        req_handler = ProxyHandler({})
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    if config.git == "github":
        url = url.replace("https://api.github.com", f"https://api.github.com/repos/{config.user}/{config.repo}/contents")











    elif config.git == "gitlab":
        raise ImportError("Not currently enabled")
        if not config.project_id:
            search_resp = json.loads(opener(f"{url}/api/v4/projects?search={config.project}").read())
            namespaced_path = f"{config.group}/{config.project}"
            for proj in search_resp:
                if proj['path_with_namespace'] == f"{config.group}/{config.project}":
                    config.project_id = proj['id']
                    break
            if not config.project_id:
                return b""
        if url.endswith("/"):
            url = url.replace(url.split("/")[2], f"{url.split("/")[2]}/api/v4/projects/{config.project_id}/repository/tree")
        else:
            url = url.replace(url.split("/")[2], f"{url.split("/")[2]}/api/v4/projects/{config.project_id}/repository/files/")
        logging.warn(url)
    






    if path:
        url = "/".join([url, path])
    if config.branch:
        url = f"{url.rstrip('/')}?ref={config.branch}"
    logging.warn(url)
    resp = opener(url).read()
    resp_json = json.loads(resp)
    if isinstance(resp_json, dict):
        resp = b64decode(resp_json['content'].encode())
    logging.warn(path_cache)
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
