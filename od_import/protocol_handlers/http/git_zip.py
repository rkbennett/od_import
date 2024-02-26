import io
import time
import logging
import zipfile
import tarfile
from html.parser import HTMLParser

########################## Protocol Handlers #########################

def git_zip(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    repo = url.split("://")[1]
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
        if 'group' not in config.__dict__:
            raise KeyError("Missing required key 'group' when git type is 'gitlab'...")
        if 'project' not in config.__dict__:
            raise KeyError("Missing required key 'project' when git type is 'gitlab'...")
        config.repo = config.project
        if config.api_key:
            config.headers["PRIVATE-TOKEN"] =f"{config.api_key}"
    if 'branch' not in config.__dict__:
        config.branch = "main"
    if len(repo.split("/")) == 2:
        url = url + "/"
    if config.git == "github":
        url = f"{url}/{config.user}/{config.repo}/archive/refs/heads/{config.branch}.zip"
    elif config.git == "gitlab":
        url = f"{url}/{config.group}/{config.project}/-/archive/{config.branch}/{config.project}-{config.branch}.zip"
    elif config.git == "gitea":
        top_level_dir = ""
        url = f"{url}/{config.user}/{config.repo}/archive/{config.branch}.zip"
    resp_obj = _core.request(url, config=config)
    if resp_obj.url.endswith("sign_in"):
        raise ImportError("Failed to authenticate")
    resp = resp_obj.read()
    if resp.startswith(b'\x50\x4b\x03\x04'):
        zip_io = io.BytesIO(resp)
        tar_io = io.BytesIO()
        zip_bytes_read = zipfile.ZipFile(zip_io, mode="r")
        tar_bytes = tarfile.open(fileobj=tar_io, mode='w:gz')
        files = [item for item in zip_bytes_read.infolist()][1:]
        for item in files:
            if config.git in ["github", "gitlab"]:
                tar_info = tarfile.TarInfo(name=item.filename.replace(f"{config.repo}-{config.branch}/", ""))
            elif config.git == "gitea":
                if not top_level_dir:
                    top_level_dir = item.filename.split("/")[0]
                tar_info = tarfile.TarInfo(name=f"{top_level_dir}/".join(item.filename.split(f"{top_level_dir}/")[1:]))
            tar_info.size = item.file_size
            tar_info.mtime = time.mktime(tuple(item.date_time) +
                (-1, -1, -1))
            tar_bytes.addfile(tarinfo=tar_info, fileobj=zip_bytes_read.open(item.filename))
        tar_bytes.close()
        zip_bytes_read.close()
        tar_io.seek(0)
        resp = tar_io.read()
    return resp
