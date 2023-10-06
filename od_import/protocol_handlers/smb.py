import io
import sys
import logging
from smb import smb_structs
from smb.SMBConnection import SMBConnection

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

########################## Protocol Handler #########################

def smb(url: str, path: str="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
    """
    Description:
        Handles smb requests for content
    Args:
        url: url to connect to for packages
        path: subpath to subpackage or nested module
        path_cache: list of paths the import hook tracks
        cache_update: unused in this module
        config: configuration options for the import hook's protocol handler (this module)
    return:
        bytes of file content or empty bytes object
    """
    stripped_proto = url.split("://")[-1]
    split_binding = stripped_proto.split("/")
    hostbinding = split_binding[0]
    share = split_binding[1]
    if len(split_binding) > 2:
        parent_path = "/".join(split_binding[2:])
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
        config.user = "guest"
    if 'password' not in config.__dict__:
        config.password = "guest"
    if 'proxy' not in config.__dict__:
        config.proxy = None
    if 'client' not in config.__dict__:
        config.client = "localhost"
    if 'nbname' not in config.__dict__:
        logging.warning("nbname config not supplied, using hostname from url")
        config.nbname = hostname
    if 'smb2' not in config.__dict__:
        config.smb2 = True

    if not config.smb2:
        smb_structs.SUPPORT_SMB2 = False

    conn = SMBConnection(config.user, config.password, config.client, config.nbname, use_ntlm_v2 = config.smb2)
    if not config.port:
        connectivity = conn.connect(ip=hostname)
    else:
        connectivity = conn.connect(ip=hostname, port=config.port)
    if not connectivity:
        logging.error("Failed to connect to host")
        return b""
    if share not in [s.name for s in conn.listShares()]:
        logging.error("%s share does not exist"% share)
        return b""
    if path or not path_cache:
        path_cache += [path + item.filename + ("/" if item.isDirectory else "") for item in conn.listPath(share, parent_path + path) if item.filename != "." and item.filename != ".."]
        return b""
    else:
        contents = io.BytesIO()
        resp = conn.retrieveFile(share, parent_path + path, contents)
        contents.seek(0)
        return contents.read()
