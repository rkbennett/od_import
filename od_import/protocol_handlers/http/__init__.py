import sys
import logging

from . import (
    git,
    git_zip,
    git_api,
    pypi,
    directory_of,
    pastebin,
    dropbox
)

########################## Protocol Handlers #########################

def http(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    helper = None
    if 'type' not in config.__dict__ or config.type == 'dir':
        helper = directory_of.directory_of
    elif 'type' in config.__dict__:
        if config.type == "git":
            helper = git.git
        elif config.type == "git_zip":
            helper = git_zip.git_zip
        elif config.type == "git_api":
            helper = git_api.git_api
        elif config.type == "pypi":
            helper = pypi.pypi
        elif config.type == "pastebin":
            helper = pastebin.pastebin
        elif config.type == "dropbox":
            helper = dropbox.dropbox
    else:
        if url.startswith("https://pypi.org"):
            helper = pypi.pypi
        elif url.startswith("https://pastbin.com"):
            helper = pastebin.pastebin
        elif url.startswith("https://dropbox.com"):
            helper = dropbox.dropbox
    if not helper:
        raise ImportError("An invalid 'type' was provided in 'http' config object")
    return helper(url, path, path_cache, cache_update, config)
