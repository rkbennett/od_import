import logging
from html.parser import HTMLParser

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
    if '_core' not in dir():
        if 'http_provider' in config.__dict__ and config.http_provider == "winhttp":
            from . import _core_winhttp as _core
        else:
            from . import _core_python as _core
    if path:
        url = "/".join([url, path])
    resp = _core.request(url, config=config).read()
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
