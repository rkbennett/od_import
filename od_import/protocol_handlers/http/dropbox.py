import json
import logging

########################## Protocol Handlers #########################

def dropbox(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if '_base_url_size' not in config.__dict__:
        config._base_url_size = len(url.split("/"))
    if 'headers' not in config.__dict__:
        config.headers = {}
    if 'access_token' not in config.__dict__:
        raise KeyError(f"Missing required key 'access_token'...")
    else:
        config.headers['Authorization'] = f"Bearer {config.access_token}"
    pre_path = url.replace("https://dropbox.com", "").replace("https://api.dropboxapi.com", "")
    if (not path_cache) or (not path and len(url.split("/")) > config._base_url_size and pre_path.endswith("/")) or (path and path.endswith("/")):
        url = "https://api.dropboxapi.com/2/files/list_folder"
        temp_headers = {"Content-Type": "application/json"}
        data = {
            "include_deleted": False,
            "include_non_downloadable_files": False,
            "recursive": True
        }
        if f"{pre_path}/{path}" == "/":
            data['path'] = ""
        else:
            data['path'] = f"{pre_path}/{path}"
        method = "POST"
    else:
        temp_headers = {}
        url = "https://content.dropboxapi.com/2/files/download"
        data = None
        if path:
            temp_headers['Dropbox-API-Arg'] = json.dumps({"path": f"{pre_path}/{path}"})
        else:
            temp_headers['Dropbox-API-Arg'] = json.dumps({"path": f"{pre_path}"})
        method = "GET"
    if path:
        path = "/".join([pre_path, path])
    else:
        path = pre_path
    resp = _core.request(url, method=method, data=data, config=config, temp_headers=temp_headers).read()
    if cache_update:
        try:
            repo_files = [item['path_display'].lstrip("/") if item['.tag'] == "file" else f"{item['path_display'].lstrip('/')}/" for item in json.loads(resp)['entries']]
            if path and path != "/":
                repo_files = [item.replace(f"{path.lstrip('/')}/", "", 1) for item in repo_files]
                repo_files = [item for item in repo_files if item]
            path_cache += repo_files
        except Exception as e:
            # do some logging
            logging.info(e)
            pass
    return resp
