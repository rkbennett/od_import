import sys
import logging
from html.parser import HTMLParser

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

from urllib.request import (
    urlopen,
    Request,
    ProxyHandler,
    build_opener,
    quote
)
from urllib.error import (
    HTTPError,
    URLError
)

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
    if 'user' not in config.__dict__:
        config.user = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
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
    if config.user:
        if config.password:
            creds = f"{quote(config.user)}:{quote(config.password)}@"
        else:
            creds = f"{config.user}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    if path:
        url = "/".join([url, path])
    resp = opener(url).read()
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
