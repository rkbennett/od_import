########################## Protocol Handlers #########################

def pastebin(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'module' not in config.__dict__:
        raise KeyError("Missing required key 'module'...")
    if 'paste_key' not in config.__dict__:
        raise KeyError("Missing required key 'paste_key'...")
    if 'visibility' not in config.__dict__ or config.visibility not in ["public", "private", "unlisted", "burn", "passworded"]:
        config.visibility == 'public'
    if config.visibility in ['private', 'burn', 'passworded']:
        if 'developer_key' not in config.__dict__:
            raise KeyError(f"Missing required key 'developer_key' when visibility set to '{config.visibility}'...")
        if 'user_key' not in config.__dict__:
            raise KeyError(f"Missing required key 'user_key' when visibility set to '{config.visibility}'...")
        if config.visibility == 'passworded':
            if 'paste_password' not in config.__dict__:
                raise KeyError(f"Missing required key 'paste_password' when visibility set to '{config.visibility}'...")
    url = "/".join(url.split("/")[:3])
    if config.visibility in ["public", "unlisted"]:
        url = f"{url}/raw/{config.paste_key}"
        resp = _core.request(url, config=config).read()
    elif config.visibility == "private":
        url = f"{url}/api/api_raw.php"
        data = {
            "api_dev_key": config.developer_key,
            "api_user_key": config.user_key,
            "api_option": "show_paste",
            "api_paste_key": config.paste_key
        }
        if config.visibility == "passworded":
            data['paste_password'] = config.paste_password
        resp = _core.request(url, method="POST", data=data, config=config).read()
    if resp:
        if f"{config.module}.py" not in path_cache:
            path_cache += [f"{config.module.replace('.', '/')}.py"]
    return resp
