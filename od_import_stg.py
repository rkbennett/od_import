import io
import sys
import json
import uuid
import time
import types
import marshal
import logging
import tarfile
import zipfile

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

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

if threedotoh:
    import importlib
elif threedotfour:
    import importlib.util

cExtensionImport = False

path_cache = []

class imp_config(object):
    """
    Description:
        A representation of import hook configurations
    """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
    
    def getConfig(self):
        return self.__dict__

def git_zip(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'git' not in config.__dict__:
        raise KeyError("Missing required key 'git'...")
    if 'headers' not in config.__dict__:
        config.headers = {'User-agent':'Python-urllib/3.x'}
    if 'api_key' not in config.__dict__:
        config.api_key = None
    if config.git == "github":
        if 'user' not in config.__dict__:
            raise KeyError("Missing required key 'user' when git type is 'github'...")
        if 'repo' not in config.__dict__:
            raise KeyError("Missing required key 'repo' when git type is 'github'...")
        if config.api_key:
            config.headers["Authorization"] =f"Bearer {config.api_key}"
    if config.git == "gitlab":
        if 'group' not in config.__dict__:
            raise KeyError("Missing required key 'group' when git type is 'gitlab'...")
        if 'project' not in config.__dict__:
            raise KeyError("Missing required key 'project' when git type is 'gitlab'...")
        config.repo = config.project
        if config.api_key:
            config.headers["PRIVATE-TOKEN"] =f"{config.api_key}"
    if 'branch' not in config.__dict__:
        config.branch = "main"
    if 'username' not in config.__dict__:
        config.username = ""
    if 'password' not in config.__dict__:
        config.password = ""
    if 'proxy' not in config.__dict__:
        config.proxy = {}
    if 'User-agent' not in config.headers:
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
    if len(repo.split("/")) == 2:
        url = url + "/"
    if config.git == "github":
        url = f"{url}/{config.user}/{config.repo}/archive/refs/heads/{config.branch}.zip"
    elif config.git == "gitlab":
        url = f"{url}/{config.group}/{config.project}/-/archive/{config.branch}/{config.project}-{config.branch}.zip"
    if config.username:
        if config.password:
            creds = f"{quote(config.username)}:{quote(config.password)}@"
        else:
            creds = f"{config.username}@"
        urlsplit = url.split('://')
        url = f"{urlsplit[0]}://{creds}{urlsplit[1]}"
    resp_obj = opener(url)
    if resp_obj.url.endswith("sign_in"):
        raise ImportError("Failed to authenticate")
    resp = resp_obj.read()
    if resp.startswith(b'\x50\x4b\x03\x04'):
        zip_io = io.BytesIO(resp)
        tar_io = io.BytesIO()
        zip_bytes_read = zipfile.ZipFile(zip_io, mode="r")
        tar_bytes = tarfile.open(fileobj=tar_io, mode='w:gz')
        files = [item for item in zip_bytes_read.infolist()][1:]
        for item in files:
            tar_info = tarfile.TarInfo(name=item.filename.replace(f"{config.repo}-{config.branch}/", ""))
            tar_info.size = item.file_size
            tar_info.mtime = time.mktime(tuple(item.date_time) +
                (-1, -1, -1))
            tar_bytes.addfile(tarinfo=tar_info, fileobj=zip_bytes_read.open(item.filename))
        tar_bytes.close()
        zip_bytes_read.close()
        tar_io.seek(0)
        resp = tar_io.read()
    return resp

class tar(object):
    
    def __init__(self, data: bytes, url_base: str, path_cache: list=[], config: object=None):
        """
        Description:
            Handles loading of tar archive and updates the import hook path cache
        Args:
            data: bytes of archive
            url_base: unused in this module
            path_cache: list of paths the import hook tracks
            config: unused in this module
        """
        self.url = url_base
        tar_io = io.BytesIO(data)
        self.tar_bytes = tarfile.open(fileobj=tar_io, mode='r:*')
        self.path_cache = path_cache + [item.name + ("/" if item.isdir() else "") for item in self.tar_bytes.getmembers()]
    
    def extractor(self, url: str, path: str="", path_cache: list=[], cache_update: bool=False, config: object=None) -> bytes:
        """
        Description:
            Handles requests for content from a tar archive object
        Args:
            url: requested path of content with full url
            path: subpath to subpackage or nested module
            path_cache: unused in this function
            cache_update: unused in this module
            config: unused in this module
        return:
            bytes of file content or empty bytes object
        """
        if path in self.path_cache:
            return b""
        return self.tar_bytes.extractfile(url.replace(self.url, "").lstrip("/")).read()


class StgImporter(object):
    """ 
    Description:
        Import meta hook class which contains required find_module and load_module functions.
        This can be added to sys.meta_path via the add_remote_source function
    Args:
        url: String which contains target url to import packages from
        INSECURE: boolean which allows unencrypted protocols to be used
        ignores: list of packages to ignore imports for
        excludes: list of packages to exclude imports of
        zip_password: bytes which contains password for decrypting zip file
        config: dictionary of configurations for the protocol handler
    """
    
    def __init__(self, url: str, INSECURE: bool=False, excludes: list=[], zip_password: bytes=None, config={}):
        self.uuid = str(uuid.uuid4().int)
        self.unique_proto_handler = 'proto_handler_' + self.uuid
        self.unique_proto_config = 'proto_config_' + self.uuid
        self.url = url.rstrip("/")
        self.modules = {}
        self.config = imp_config(**config)
        self.INSECURE = INSECURE
        self.bootcode_added = []
        self._boot_code = []
        self.path_cache = []
        self.excludes = excludes
        self.proto_handler, secure = self.protocol_resolver(self.url)
        sys.modules[self.unique_proto_handler] = self.proto_handler
        sys.modules[self.unique_proto_config] = self.config
        if isinstance(zip_password, str):
            self.zip_password = bytes(zip_password, 'utf-8')
        elif isinstance(zip_password, bytes) or zip_password is None:
            self.zip_password = zip_password
        else:
            raise ValueError("[-] zip_password must be one of String, Bytes, or None")
        if not secure and not self.INSECURE:
            raise ImportError("[-] Insecure protocol used without setting INSECURE")
        resp = self.proto_handler(self.url, path_cache=self.path_cache, config=self.config)
        # Check if file is a zip
        if resp.startswith(b'\x1f\x8b') or (len(resp) > 260 and resp[257:].startswith(b"ustar")):
            archive_handler = tar(resp, self.url, self.path_cache)
            self.path_cache = archive_handler.path_cache
            self.proto_handler = archive_handler.extractor
    
    def protocol_resolver(self, url: str):
        """ 
        Description:
            Determines the appropriate handler based on the supplied url protocol
        Returns:
            function: A function which handles imports based on a matched protocol
        """
        uri_array = url.split("://")
        if len(uri_array) != 2:
            raise ValueError("%s is not a valid uri", url)
        proto = uri_array[0]
        return git_zip, proto in ["https"]
        raise ValueError(f"{proto} is not a supported protocol")
    
    def hook(self, mod: str, path: str):
        """
        Description:
            determines if an function requires a dynamic patch to be imported
        Args:
            mod: name of the module being imported
            path: file path of the module to be imported
        """
        pass
    
    def add_bootcode(self, code: str):
        """
        Description:
            Add some code that will patch imported modules.
        Args:
            code: code to be use to patch imported modules"""
        self._boot_code.append(code)
    
    def _get_module_content(self, fullname: str):
        """
        Description:
            This function just returns the raw content of a c extension.
            It is used by _memimporter for an import from memory
        Args:
            fullname: module/package name to load
        Returns:
            raw contents of c extension"""
        return self.modules[fullname.replace("/",".")]['content']
        
    def find_module(self, fullname: str, path: str=None):
        """
        Description:
            Determines if this import meta hook can load the requested module
        Args:
            fullname: name of module being imported
            path: file path of module being imported
        Returns:
            self if the module can be loaded or None if the module cannot be loaded
        """
        if self.path_cache:
            depth = 1
            path = fullname.replace(".","/")
            while depth <= len(path.split("/")):
                if "/".join(path.split("/")[:depth]) == path:
                    mods = [mod for mod in self.path_cache if mod.startswith(path)]
                    c_mods = [mod for mod in self.path_cache if mod.startswith(path) and (mod.split("/")[depth - 1].endswith(".dll") or mod.split("/")[depth - 1].endswith(".pyd"))]
                    if mods:
                        if path + ".py" in mods:
                            self.modules[fullname] = {}
                            self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + path + ".py", path_cache=self.path_cache, config=self.config)
                            self.modules[fullname]['filepath'] = self.url + "/" + path + ".py"
                            self.modules[fullname]['package'] = False
                            self.modules[fullname]['cExtension'] = False
                            return self
                        elif cExtensionImport and c_mods: # or mod.endswith('.so')): #not currently supporting *nix
                            self.modules[fullname] = {}
                            self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + c_mods[0], path_cache=self.path_cache, config=self.config)
                            self.modules[fullname]['filepath'] = self.url + "/" + c_mods[0]
                            self.modules[fullname]['package'] = False
                            self.modules[fullname]['cExtension'] = True
                            return self
                        elif path + "/" in mods:
                            # Let's try to update the cache
                            self.proto_handler(self.url, path=path + "/", path_cache=self.path_cache, config=self.config)
                            if path + "/__init__.py" in self.path_cache:
                                self.modules[fullname] = {}
                                self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + path + "/__init__.py", path_cache=self.path_cache, config=self.config)
                                self.modules[fullname]['filepath'] = self.url + "/" + path + "/__init__.py"
                                self.modules[fullname]['package'] = True
                                self.modules[fullname]['cExtension'] = False
                                return self
                else:
                    if (("/".join(path.split("/")[:depth]) + "/" in self.path_cache) or ("/".join(path.split("/")[:depth]) in self.path_cache)):
                        # Try to update cache
                        self.proto_handler(self.url, path="/".join(path.split("/")[:depth]) + "/", path_cache=self.path_cache, config=self.config)
                        if not [mod for mod in self.path_cache if mod.startswith("/".join(path.split("/")[:depth]))]:
                            # the path couldn't be matched at the current depth
                            logging.info("%s couldn't be matched at the current depth" % "/".join(path.split("/")[:depth]))
                            break
                depth += 1
        return None
    
    def load_module(self, fullname: str):
        """
        Description:
            Loads module into current namespace
        Args:
            fullname: name of the module/package to load
        Return:
            Returns module object with loaded/executed code within the module namespace"""
        if fullname not in self.modules:
            raise ImportError("Failed to load module %s from %s" % (fullname, self.url))
        import_module = self.modules[fullname]
        mod = types.ModuleType(fullname)
        mod.__loader__ = self
        mod.__file__ = import_module['filepath']
        mod.__path__ = "/".join(import_module['filepath'].split("/")[:-1]) + "/"
        if import_module['package']:
            mod.__package__ = fullname
        else:
            #recursively find the package
            if len(fullname.split('.')[:-1]) > 1:
                pkg_name = '.'.join(fullname.split('.')[:-1])
                while sys.modules[pkg_name].__package__ != pkg_name:
                    pkg_name = '.'.join(pkg_name.split('.')[:-1])
                mod.__package__ = pkg_name
            else:
                mod.__package__ = fullname.split('.')[0]
        
        # Handle dynamic patching, if required
        if mod.__name__ not in self.bootcode_added:
            self.hook(mod, self.url)
            if self._boot_code:
                self.bootcode_added.append(mod.__name__)
                for boot_code in self._boot_code:
                    if mod.__name__ == mod.__package__:
                        exec(boot_code, globals())
                self._boot_code = []
    
        if import_module['cExtension']:
            self.path = mod.__file__
            fpath = fullname.replace(".","/")
            try:
                spec = importlib.util.find_spec(fullname, fpath)
            except:
                spec = importlib.find_loader(fullname, fpath)
            initname = f"PyInit_{fullname.split('.')[-1]}"
            mod = _memimporter.import_module(fullname, fpath, initname, self._get_module_content, spec)
            mod.__name__ = fullname
            sys.modules[fullname] = mod
        else:
            self.path = mod.__file__
            sys.modules[fullname] = mod
            exec(import_module['content'], mod.__dict__)
        if fullname in self.modules:
            # release loaded module
            self.modules.pop(fullname)
        return mod


base_url = "https://github.com"
repo = "od_import"
user = "rkbennett"
stg_importer = StgImporter(base_url, config={"user": user, "repo": repo, "git": "github", "type": "git_zip"})
sys.meta_path.insert(0, stg_importer)
import od_import

