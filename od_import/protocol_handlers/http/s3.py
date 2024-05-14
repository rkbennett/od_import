import hmac
import hashlib
import logging
from datetime import (
    datetime,
    timezone
)
import xml.etree.ElementTree as ET

newline = "\n"

########################## Protocol Handlers #########################

def _element_to_dict(element):
    if len(element) == 0:
        return element.text
    result = {}
    for child in element:
        child_result = _element_to_dict(child)
        if child.tag.split("}")[-1] in result:
            if isinstance(result[child.tag.split("}")[-1]], list):
                result[child.tag.split("}")[-1]].append(child_result)
            else:
                result[child.tag.split("}")[-1]] = [result[child.tag.split("}")[-1]], child_result]
        else:
                result[child.tag.split("}")[-1]] = child_result
    return result

def s3(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'access_key' not in config.__dict__:
        raise KeyError(f"Missing required key 'access_key'...")
    if 'secret_key' not in config.__dict__:
        raise KeyError(f"Missing required key 'secret_key'...")
    if 'bucket' not in config.__dict__:
        raise KeyError(f"Missing required key 'bucket'...")
    if 'region' not in config.__dict__:
        raise KeyError(f"Missing required key 'region'...")
    date = datetime.now(timezone.utc)
    config.headers['X-Amz-Date'] = date.strftime('%Y%m%dT%H%M%SZ')
    config.headers['Host'] = f"{config.bucket}.s3.{config.region}.{url.replace('https://', '').replace('http://', '')}".split("/")[0]
    config.headers['X-Amz-Content-Sha256'] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sorted_headers = ["Host", "X-Amz-Content-Sha256", "X-Amz-Date"]
    if not path and len(url.split("/")) > config._base_url_size:
        request_path = "/" + "/".join(url.split("/")[config._base_url_size:])
    elif path:
        request_path = path
    else:
        request_path = "/"
    if request_path != "/" and request_path.endswith("/"):
        return b""
    canonical_request = f"GET\n{request_path}\n{'encoding-type=url' if request_path == '/' else ''}\n{newline.join([f'{key.lower()}:{config.headers[key].strip()}' for key in sorted_headers])}\n\n{(';'.join(sorted_headers)).lower()}\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    signature_string = f"AWS4-HMAC-SHA256\n{date.strftime('%Y%m%dT%H%M%SZ')}\n{date.strftime('%Y%m%d')}/{config.region}/s3/aws4_request\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    date_key = hmac.new((f"AWS4{config.secret_key}").encode(), date.strftime("%Y%m%d").encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, config.region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(signing_key, signature_string.encode(), hashlib.sha256).hexdigest()
    config.headers['Authorization'] = f"AWS4-HMAC-SHA256 Credential={config.access_key}/{date.strftime('%Y%m%d')}/{config.region}/s3/aws4_request,SignedHeaders={(';'.join(sorted_headers)).lower()},Signature={signature}"
    if (not path_cache):
        url = f"https://{config.bucket}.s3.{config.region}.{url.replace('https://', '').replace('http://', '')}/?encoding-type=url"
    else:
        url = f"https://{config.bucket}.s3.{config.region}.{url.replace('https://', '').replace('http://', '')}{'/' if path else ''}{path.strip('/')}"
    resp = _core.request(url, config=config).read()
    if cache_update:
        try:
            path_list = []
            path_list += [f"{path['Key']}" for path in _element_to_dict(ET.fromstring(resp))['Contents']]
            path_list += list(set(f"{'/'.join(path.split('/')[:-1])}/" for path in path_list))
            path_cache += path_list
        except Exception as e:
            logging.info(e)
            pass
    return resp