import sys
import ssl
import logging
import time
from html.parser import HTMLParser

GET_FILE_MAX_ATTEMPTS = 3
GET_FILE_MAX_WAIT = 0.5

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

try:
    from httplib import IncompleteRead
except ImportError:
    from http.client import IncompleteRead

########################## link parser ###############################

class LinkScrape(HTMLParser):
    """
    Description:
        Parses html for directory links
    Args:
        HTMLParser object
    return:
        This object
    """
    def __init__(self):
        HTMLParser.__init__(self)
        self.data = []

    def handle_starttag(self, tag, attrs):
        """
        Description:
            Builds list of link objects
        Args:
            tag: html tag to parse
            attrs: attributes of tag
        """
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    link = attr[1]
                    if 'data' not in dir(self):
                        self.data = []
                    try:
                        self.data.append(link)
                    except Exception as e:
                        logging.error(e)

########################## Protocol Handlers #########################

def directory_of(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'username' not in config.__dict__:
        config.username = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    elif 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if 'verify' not in config.__dict__:
        config.verify = True
    if 'ca_file' not in config.__dict__:
        config.ca_file = None
    if 'ca_data' not in config.__dict__:
        config.ca_data = None
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
    elif url.startswith("https://"):
        if not config.verify:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif config.ca_file or config.ca_data:
            ssl_context = ssl.create_default_context(cafile=config.ca_file, cadata=config.ca_data)
        else:
            ssl_context = None
        req_handler = HTTPSHandler(context=ssl_context)
    else:
        req_handler = HTTPHandler()
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    if path:
        url = "/".join([url, path])

    for attemps in range(GET_FILE_MAX_ATTEMPTS):
        try:
            resp = opener(url).read()
            break
        except IncompleteRead as e:
            logging.info(e)
            if attemps == GET_FILE_MAX_ATTEMPTS - 1:
                raise e

        try:
            time.sleep(GET_FILE_MAX_WAIT)
        except OSError as e:
            logging.error(e)
            continue

    if cache_update:
        try:
            # attempt to parse links on the page
            link_parser = LinkScrape()
            link_parser.feed(resp.decode('utf-8'))
            if path:
                path_cache += [path.rstrip("/") + "/" + link for link in link_parser.data]
            else:
                path_cache += link_parser.data
        except Exception as e:
            # do some logging
            logging.info(e)
            pass
    return resp
