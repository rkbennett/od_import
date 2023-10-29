import io
import sys
import logging
from ftplib import FTP, FTP_TLS

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

########################## Protocol Handlers #########################

def ftp(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
    """
    Description:
        Handles ftp requests for content
    Args:
        url: url to connect to for packages
        path: subpath to subpackage or nested module
        path_cache: list of paths the import hook tracks
        cache_update: unused in this module
        config: configuration options for the import hook's protocol handler (this module)
    return:
        bytes of file content or empty bytes object
    """
    proto, stripped_proto = url.split("://")
    split_binding = stripped_proto.split("/")
    hostbinding = split_binding[0]
    if len(split_binding) > 1:
        parent_path = "/".join(split_binding[1:])
    else:
        parent_path = "/"
    hostbinding_list = hostbinding.split(":")
    hostname = hostbinding_list[0]
    if len(hostbinding_list) > 1:
        port = hostbinding_list[-1]
    else:
        port = None
    if 'port' not in config.__dict__:
        config.port = port
    if 'user' not in config.__dict__:
        config.user = "anonymous"
    if 'password' not in config.__dict__:
        config.password = ""
    if 'proxy' not in config.__dict__:
        config.proxy = None

    conn_args = {
        "host": hostname
    }
    auth_args = {
        "user": config.user,
        "passwd": config.password
    }
    if config.port:
        conn_args['port'] = config.port

    if proto == "ftps":
        ftp_class = FTP_TLS
    else:
        ftp_class = FTP
    with ftp_class() as ftp:
        ftp.connect(**conn_args)
        ftp.login(**auth_args)

        if path or not path_cache:
            path_cache += [path + file + ("/" if fileAttr["type"] == "dir" else "") for file, fileAttr in ftp.mlsd(parent_path + path)]
            resp = b""
        else:
            contents = io.BytesIO()
            ftp.retrbinary("RETR %s"% parent_path + path, contents.write)
            contents.seek(0)
            resp = contents.read()

    return resp
