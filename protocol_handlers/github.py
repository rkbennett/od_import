import sys
import ssl
import json
import logging
from html.parser import HTMLParser

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
        self.repo = None
        self.branch = None
        self.fetch_data = False

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
                    if attr[1].startswith(f"{self.repo}/tree/{self.branch}") or attr[1].startswith(f"{self.repo}/blob/{self.branch}"):
                        link = attr[1]
                        if 'data' not in dir(self):
                            self.data = []
                        try:
                            self.data.append(link)
                        except Exception as e:
                            logging.error(e)
        elif tag == 'script' and ('data-target', 'react-app.embeddedData') in attrs:
            self.fetch_data = True
    
    def handle_data(self, data):
        if self.fetch_data:
            self.data = [item['path'] if item['contentType'] == 'file' else f"{item['path']}/" for item in json.loads(data)['payload']['tree']['items']]
            self.fetch_data = False

########################## Protocol Handlers #########################

def github(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    repo = url.split("://")[1]
    if 'user' not in config.__dict__:
        config.user = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'cert' not in config.__dict__:
        config.cert = None
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    elif 'User-agent' not in config.headers:
        config.headers['User-agent'] = 'Python-urllib/3.x'
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if 'branch' not in config.__dict__:
        config.branch = "main"
    if config.proxy and 'url' in config.proxy:
        req_handler = ProxyHandler({config.proxy['url'].split('://')[0]:config.proxy['url']})
    else:
        req_handler = ProxyHandler({})
    if config.api_key:
        config.headers["Authorization"] =f"Bearer {config.api_key}"
    req_opener = build_opener(req_handler)
    if config.headers:
        req_opener.addheaders = [(header, value) for header, value in config.headers.items()]
    opener = req_opener.open
    if len(repo.split("/")) == 2:
        url = url + "/"
    if not path and not url.endswith("/"):
        project = "/".join(repo.split("/")[:2])
        url = url.replace("github:/", "https://raw.githubusercontent.com").replace(project, f"{project}/{config.branch}")
    else:
        url = f"""{url.replace("github:/", "https://github.com")}tree/{config.branch}/"""
    if config.user:
        if config.password:
            creds = f"{quote(config.user)}:{quote(config.password)}@"
        else:
            creds = f"{config.user}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    if path:
        url = url + path
    resp = opener(url).read()
    if cache_update:
        try:
            # attempt to parse links on the page
            link_parser = LinkScrape()
            link_parser.repo = f"/{repo}"
            link_parser.branch = config.branch
            link_parser.feed(resp.decode('utf-8'))
            file_path = f"{repo}/blob/{config.branch}"
            folder_path = f"{repo}/tree/{config.branch}"
            file_links = [f"""{link.split(file_path)[-1]}""" for link in link_parser.data]
            github_path_set = set([f"""{link.split(folder_path)[-1].lstrip("/")}/""" if len(link.split(folder_path)) == 2 else link.lstrip("/") for link in file_links])
            github_paths = [path for path in github_path_set]
            path_cache += github_paths
            pass
        except Exception as e:
            # do some logging
            logging.info(e)
            pass
    return resp
