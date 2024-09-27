import io
import sys
import logging

########################## Protocol Handler #########################

def mem(url: str, path: str="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
    """
    Description:
        Handles memory requests for content
    Args:
        url: unused for this module, should always be mem://python
        path: subpath to subpackage or nested module
        path_cache: list of paths the import hook tracks
        cache_update: unused in this module
        config: configuration options for the import hook's protocol handler (this module)
    return:
        bytes of file content or empty bytes object
    """
    stripped_proto = url.split("://")[-1]
    split_path = stripped_proto.split("/")
    if len(split_path) > 1:
        parent_path = "/".join(split_path[1:])
    else:
        parent_path = "/"
    if 'data' not in config.__dict__:
        logging.error("Config missing required key 'data'")
        return b""
    if path or not path_cache:
        if isinstance(config.data, bytes) and (config.data.startswith(b'\x50\x4b\x03\x04') or config.data.startswith(b'\x1f\x8b') or (len(config.data) > 260 and config.data[257:].startswith(b"ustar"))):
            return config.data
        elif isinstance(config.data, dict):
            path_cache += [key for key in config.data.keys()]
            return b""
        elif 'file_name' in config.__dict__ and config.file_name and isinstance(config.file_name, str):
            path_cache += [f"{(config.file_name).lstrip('/')}"]
            return b""
        else:
            logging.error("Config requires key 'file_name' if single file is passed as variable")
            return b""
    else:
        if isinstance(config.data, dict):
            return config.data[parent_path + path]
        elif 'file_name' in config.__dict__ and config.file_name and isinstance(config.file_name, str):
            return config.data
