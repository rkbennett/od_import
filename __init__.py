import io
import sys
import uuid
import types
import marshal
import logging
from . import hooks
from contextlib import contextmanager

threedotoh = (sys.version_info.major == 3 and sys.version_info.minor < 4)
threedotfour = (sys.version_info.major == 3 and sys.version_info.minor >= 4)

if threedotoh:
    import importlib
elif threedotfour:
    import importlib.util

########################## Check for _memimporter for pyd/dll support ##################
try:
    #check if importable
    import _memimporter
    cExtensionImport = True
    logging.info("[!] memory imports loaded")
except:
    try:
        #check if builtin
        _memimporter
        cExtensionImport = True
        logging.info("[!] memory imports loaded")
    except:
        cExtensionImport = False
        logging.warning("[!] memory imports not loaded, some packages may not work")

########################## path cache ################################

path_cache = []

########################## Protocol abstractors ######################
def http():
    """ 
    Description:
        Handles loading of dependencies of http protocol handler
    Returns:
        function: A function which handles http-based imports
    """
    from .protocol_handlers import http
    return http.http

def github():
    """ 
    Description:
        Handles loading of dependencies of github protocol handler
    Returns:
        function: A function which handles github-based imports
    """
    from .protocol_handlers import github
    return github.github

def github_zip():
    """ 
    Description:
        Handles loading of dependencies of github_zip protocol handler
    Returns:
        function: A function which handles github zip-based imports
    """
    from .protocol_handlers import github_zip
    return github_zip.github_zip

def github_api():
    """ 
    Description:
        Handles loading of dependencies of github protocol handler
    Returns:
        function: A function which handles github-based imports
    """
    from .protocol_handlers import github_api
    return github_api.github_api

def smb():
    """ 
    Description:
        Handles loading of dependencies of http protocol handler
    Returns:
        function: A function which handles http-based imports
    """
    from .protocol_handlers import smb
    return smb.smb

def ftp():
    """ 
    Description:
        Handles loading of dependencies of ftp protocol handler
    Returns:
        function: A function which handles ftp-based imports
    """
    from .protocol_handlers import ftp
    return ftp.ftp

########################## Archive abstractors ######################
def zip_handler():
    """ 
    Description:
        Handles loading of dependencies of zip archive handler
    Returns:
        function: A function which handles zip parsing
    """
    from .archive_providers import ziph
    return ziph.ziph

def tar_handler():
    """ 
    Description:
        Handles loading of dependencies of tar archive handler
    Returns:
        function: A function which handles tar parsing
    """
    from .archive_providers import tar
    return tar.tar

########################## Static objects ############################

supported_protos = {
    "http": ["http","https"],
    "smb": ["smb"],
    "ftp": ["ftp"],
    "github": ["github"],
    "github_zip": ["github_zip"],
    "github_api": ["github_api"]
}

proto_handlers = {
    "http": http,
    "smb": smb,
    "ftp": ftp,
    "github": github,
    "github_zip": github_zip,
    "github_api": github_api
}

archive_handlers = {
    "zip": zip_handler,
    "tar": tar_handler
}

secure_protos = [
    "https",
    "github",
    "github_zip"
    "github_api"
]

########################## Config class ##############################
class imp_config(object):
    """
    Description:
        A representation of import hook configurations
    """

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def getConfig(self):
        return self.__dict__

########################## Importer ##################################

class ODImporter(object):
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

    def __init__(self, url: str, INSECURE: bool=False, ignores: list=None, excludes: list=[], zip_password: bytes=None, config={}):
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
        self.ignores = ignores if ignores is not None else []
        hooks.init_finder(self)
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
        if resp.startswith(b'\x50\x4b\x03\x04'):
            archive_handler = archive_handlers['zip']()(resp, self.url, self.path_cache, pwd=self.zip_password)
            self.path_cache = archive_handler.path_cache
            self.proto_handler = archive_handler.extractor
        # Check if file is a tar or tgz
        elif resp.startswith(b'\x1f\x8b') or (len(resp) > 260 and resp[257:].startswith(b"ustar")):
            archive_handler = archive_handlers['tar']()(resp, self.url, self.path_cache)
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
        for supported_proto in supported_protos:
            if proto in supported_protos[supported_proto]:
                return proto_handlers[supported_proto](), proto in secure_protos
        raise ValueError(f"{proto} is not a supported protocol")

    def ignore(self, name: str):
        """If the module or package with the given name is not found,
        don't record this as an error.  If is is found, however,
        include it.
        """
        self.ignores.append(name)

    def hook(self, mod: str, path: str):
        """
        Description:
            determines if an function requires a dynamic patch to be imported
        Args:
            mod: name of the module being imported
            path: file path of the module to be imported
        """
        hookname = "hook_%s" % mod.__name__.replace(".", "_")
        mth = getattr(hooks, hookname, None)
        if mth:
            mth(self, mod, path, self.unique_proto_handler, self.unique_proto_config)

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


def add_remote_source(url: str, INSECURE: bool=False, return_importer: bool=False, zip_password: bytes=None, config: dict={}):
    """
    Description:
        Creates an ODImporter object and inserts it into the first entry of sys.meta_path
    Args:
        url: Url of remote source
        INSECURE: boolean which allows insecure protocols to be used for remote imports
        return_importer: boolean which determines if the importer object should be returned (used for internal calls)    
    """
    importer = ODImporter(url, INSECURE, zip_password=zip_password, config=config)
    sys.meta_path.insert(0, importer)
    if return_importer:
        return importer

def remove_remote_source(url: str):
    """
    Description:
        Removes ODImporter object from sys.meta_path and the unique_proto_handler from sys.modules
    Args:
        url: Url of remote source
    """
    for import_hook in sys.meta_path:
        if 'url' in dir(import_hook) and import_hook.url == url:
            try:
                del sys.modules[import_hook.unique_proto_handler]
                sys.meta_path.remove(import_hook)
                return
            except Exception as e:
                logging.warning("Failed to remove import hook or proto_handler for %s"% import_hook.url)
                logging.warning(e)

@contextmanager
def remote_source(url: str, INSECURE: bool=False, zip_password: bytes=None, config: dict={}):
    """
    Description:
        Allows for temporary import hooking to run imports/commands within a limited namespace scope
    Args:
        url: The url of the target source
    """
    import_hook = add_remote_source(url, INSECURE=INSECURE, return_importer=True, zip_password=zip_password, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

