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

from urllib.parse import quote_plus as urlencode

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
    if config.git in ["github", "gitea"]:
        if 'user' not in config.__dict__:
            raise KeyError(f"Missing required key 'user' when git type is '{config.git}'...")
        if 'repo' not in config.__dict__:
            raise KeyError(f"Missing required key 'repo' when git type is '{config.git}'...")
        if config.api_key:
            config.headers["Authorization"] = f"Bearer {config.api_key}" if config.git == "gitlab" else f"token {config.api_key}"
    if config.git == "gitlab":
        if ('group' not in config.__dict__ or 'project' not in config.__dict__) and 'project_id' not in config.__dict__:
            raise KeyError("Missing required key(s) 'group' and 'project' required when git type is 'gitlab' and 'project_id' key not set...")
        if config.api_key:
            config.headers["PRIVATE-TOKEN"] =f"{config.api_key}"
        if 'project_id' not in config.__dict__:
            config.project_id = None
    if 'branch' not in config.__dict__:
        if config.git == "github":
            config.branch = None
        else:
            config.branch = "main"
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
    if config.git == "github":
        url = url.replace("https://api.github.com", f"https://api.github.com/repos/{config.user}/{config.repo}/contents")
        if path:
            url = "/".join([url, path])
        if config.branch:
            url = f"{url.rstrip('/')}?ref={config.branch}"
    elif config.git == "gitlab":
        if not config.project_id:
            search_resp = json.loads(opener(f"{url}/api/v4/projects?search={config.project}").read())
            namespaced_path = f"{config.group}/{config.project}"
            for proj in search_resp:
                if proj['path_with_namespace'] == f"{config.group}/{config.project}":
                    config.project_id = proj['id']
                    break
            if not config.project_id:
                return b""
        if (url.endswith("/") or len(url.split("/")) == 3 and not path) or (path and path.endswith("/")):
            url = url.replace(url.split("/")[2], f"{url.split('/')[2]}/api/v4/projects/{config.project_id}/repository/tree?ref={config.branch}")
            if path:
                url = f"{url}&path={urlencode(path)}"
        else:
            url_path = url.split(url.split("/")[2])[1]
            url = url.replace(url.split("/")[2], f"{url.split('/')[2]}/api/v4/projects/{config.project_id}/repository/files/")
            if url_path:
                url = url.replace(url_path, f"{urlencode(url_path.lstrip('/'))}")
                url = f"{url}?ref={config.branch}"
    elif config.git == "gitea":
        if (url.endswith("/") or len(url.split("/")) == 3 and not path) or (path and path.endswith("/")):
            url = url.replace(url.split("/")[2], f"{url.split('/')[2]}/api/v1/repos/{config.user}/{config.repo}/contents?ref={config.branch}")
            if path:
                url = f"/{urlencode(path.rstrip('/'))}?".join(url.split("?"))
        else:
            url_path = url.split(url.split("/")[2])[1]
            url = url.replace(url_path, f"/api/v1/repos/{config.user}/{config.repo}/contents/{urlencode(url_path)}?ref={config.branch}")
    resp = opener(url).read()
    resp_json = json.loads(resp)
    if isinstance(resp_json, dict):
        resp = b64decode(resp_json['content'].encode())
    if cache_update:
        try:
            # attempt to parse links on the page
            if config.git in ["github", "gitea"]:
                repo_files = [item['path'] if item['type'] == "file" else f"{item['path']}/" for item in json.loads(resp)]
            else:
                repo_files = [item['path'] if item['type'] == "blob" else f"{item['path']}/" for item in json.loads(resp)]
            path_cache += repo_files
        except Exception as e:
            # do some logging
            logging.info(e)
            pass
    return resp
