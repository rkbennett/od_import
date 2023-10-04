import sys
import logging

from . import (
    git_zip,
    directory_of
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
        if config.type == "git_zip":
            helper = git_zip.git_zip
    if not helper:
        raise ImportError("An invalid 'type' was provided in 'http' config object")
    return helper(url, path, path_cache, cache_update, config)
