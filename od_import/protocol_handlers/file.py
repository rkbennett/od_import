import logging

########################## Protocol Handlers #########################

def read_file(path: str, path_cache = "", config = "") -> bytes:
    """
    Description:
        Reads local file content
    Args:
        path: path to the local file
    return:
        bytes of file content or empty bytes object
    """
    path = path[7:]
        
    try:
        with open(path, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        logging.error(f"File {path} not found.")
        return b""
