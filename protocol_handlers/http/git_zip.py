import io
import sys
import ssl
import json
import time
import logging
import zipfile
import tarfile
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
    repo = url.split("://")[1]
    if 'git' not in config.__dict__:
        raise KeyError("Missing required key 'git'...")
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if config.git == "github":
        if 'user' not in config.__dict__:
            raise KeyError("Missing required key 'user' when git type is 'github'")
        if config.api_key:
            config.headers["Authorization"] =f"Bearer {config.api_key}"
    if config.git == "gitlab":
        if 'group' not in config.__dict__:
            raise KeyError("Missing required key 'group' when git type is 'gitlab'...")
        if 'project' not in config.__dict__:
            raise KeyError("Missing required key 'project' when git type is 'gitlab'...")
        if config.api_key:
            config.headers["PRIVATE-TOKEN"] =f"{config.api_key}"
    if 'repo' not in config.__dict__:
        raise KeyError("Missing required key 'repo'...")
    if 'branch' not in config.__dict__:
        config.branch = "main"
    if 'username' not in config.__dict__:
        config.username = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    elif 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
    else:
        req_handler = ProxyHandler({})          
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    if len(repo.split("/")) == 2:
        url = url + "/"
    if config.git == "github":
        url = f"{url}/{config.user}/{config.repo}/archive/refs/heads/{config.branch}.zip"
    elif config.git == "gitlab":
        url = f"{url}/{config.group}/{config.project}/{config.repo}/-/archive/{config.branch}/{config.repo}-{config.branch}.zip"
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    resp_obj = opener(url)
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
            tar_info = tarfile.TarInfo(name=item.filename.replace(f"{config.repo}-{config.branch}/", ""))
            tar_info.size = item.file_size
            tar_info.mtime = time.mktime(tuple(item.date_time) +
                (-1, -1, -1))
            tar_bytes.addfile(tarinfo=tar_info, fileobj=zip_bytes_read.open(item.filename))
        tar_bytes.close()
        zip_bytes_read.close()
        tar_io.seek(0)
        resp = tar_io.read()
    return resp
