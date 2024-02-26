import json
import logging
from base64 import b64decode
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
    if '_core' not in dir():
        if 'http_provider' in config.__dict__ and config.http_provider == "winhttp":
            from . import _core_winhttp as _core
        else:
            from . import _core_python as _core
    if 'headers' not in config.__dict__:
        config.headers = {}
    if 'git' not in config.__dict__:
        raise KeyError("Missing required key 'git'...")
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if config.git in ["github", "gitea"]:
        if 'user' not in config.__dict__:
            raise KeyError(f"Missing required key 'user' when git type is '{config.git}'...")
        if 'repo' not in config.__dict__:
            raise KeyError(f"Missing required key 'repo' when git type is '{config.git}'...")
        if config.api_key:
            config.headers["Authorization"] = f"Bearer {config.api_key}" if config.git == "github" else f"token {config.api_key}"
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
    if config.git == "github":
        url = url.replace("https://api.github.com", f"https://api.github.com/repos/{config.user}/{config.repo}/contents")
        if path:
            url = "/".join([url, path])
        if config.branch:
            url = f"{url.rstrip('/')}?ref={config.branch}"
    elif config.git == "gitlab":
        if not config.project_id:
            search_resp = json.loads(_core.request(f"{url}/api/v4/projects?search={config.project}", config=config).read())
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
    resp = _core.request(url, config=config).read()
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
