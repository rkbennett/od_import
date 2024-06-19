import io
import sys
import uuid
import types
import marshal
import logging
from . import hooks
import importlib.util
import _frozen_importlib
from contextlib import contextmanager

threedotsix = (sys.version_info.major == 3 and sys.version_info.minor < 12)
threedottwelve = (sys.version_info.major == 3 and sys.version_info.minor >= 12)

if threedottwelve:
    import importlib.machinery

########################## Check for _memimporter for pyd/dll support ##################
try:
    #check if importable
    import _memimporter
    globals()['raw_python_import'] = False
    cExtensionImport = True
    logging.info("[!] memory imports loaded")
except:
    try:
        #check if builtin
        _memimporter
        cExtensionImport = True
        globals()['raw_python_import'] = False
        logging.info("[!] memory imports loaded")
    except:
        try:
            pythonmemimporter
            _memimporter = pythonmemimporter._memimporter()
            cExtensionImport = True
            globals()['raw_python_import'] = True
            logging.info("[!] memory imports loaded")
        except:
            try:
                from pythonmemimporter import _memimporter
                _memimporter = _memimporter()
                cExtensionImport = True
                globals()['raw_python_import'] = True
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

def pip_handler():
    """ 
    Description:
        Handles loading of dependencies of pip protocol handler
    Returns:
        function: A function which handles pip-based imports
    """
    from .protocol_handlers import pip_handler
    return pip_handler.pip_handler

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
    "ftp": ["ftp", "ftps"],
    "pip": ["pip"]
}

proto_handlers = {
    "http": http,
    "smb": smb,
    "ftp": ftp,
    "pip": pip_handler
}

archive_handlers = {
    "zip": zip_handler,
    "tar": tar_handler
}

secure_protos = [
    "https",
    "ftps",
    "pip"
]

wrapper_protos = [
    "pip"
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
        if len(uri_array) != 2 and uri_array[0] not in wrapper_protos:
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
            return mod.__name__
        return None

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
    
    if threedottwelve:
        def find_spec(self, fullname: str, path: str=None, target: object=None):
            """
            Description:
                Determines if this import meta hook can load the requested module
            Args:
                fullname: name of module being imported
                path: file path of module being imported
            Returns:
                ModuleSpec object if the module can be loaded or None if the module cannot be loaded
            """
            if self.path_cache and fullname not in self.excludes:
                depth = 1
                path = fullname.replace(".","/")
                package_spec = importlib.machinery.ModuleSpec(fullname, self)
                package_spec.cached = None
                while depth <= len(path.split("/")):
                    if "/".join(path.split("/")[:depth]) == path:
                        mods = [mod for mod in self.path_cache if mod.startswith(path)]
                        c_mods = [mod for mod in self.path_cache if mod.startswith(path) and (mod.split("/")[depth - 1].endswith(".dll") or mod.split("/")[depth - 1].endswith(".pyd"))]
                        pyc_mods = [mod for mod in self.path_cache if mod.startswith(path) and mod.split("/")[depth - 1].endswith(".pyc")]
                        if mods:
                            if path + ".py" in mods:
                                self.modules[fullname] = {}
                                self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + path + ".py", path_cache=self.path_cache, config=self.config)
                                self.modules[fullname]['filepath'] = self.url + "/" + path + ".py"
                                self.modules[fullname]['package'] = False
                                self.modules[fullname]['cExtension'] = False
                                package_spec.origin = self.modules[fullname]['filepath']
                                package_spec.has_location = True
                                return package_spec
                            elif cExtensionImport and c_mods: # or mod.endswith('.so')): #not currently supporting *nix
                                self.modules[fullname] = {}
                                self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + c_mods[0], path_cache=self.path_cache, config=self.config)
                                self.modules[fullname]['filepath'] = self.url + "/" + c_mods[0]
                                self.modules[fullname]['package'] = False
                                self.modules[fullname]['cExtension'] = True
                                package_spec = _frozen_importlib.ModuleSpec(fullname, self, origin=self.url + "/" + c_mods[0], is_package=False)
                                return package_spec
                            elif path + "/" in mods:
                                # Let's try to update the cache
                                self.proto_handler(self.url, path=path + "/", path_cache=self.path_cache, config=self.config)
                                if path + "/__init__.py" in self.path_cache:
                                    self.modules[fullname] = {}
                                    self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + path + "/__init__.py", path_cache=self.path_cache, config=self.config)
                                    self.modules[fullname]['filepath'] = self.url + "/" + path + "/__init__.py"
                                    self.modules[fullname]['package'] = True
                                    self.modules[fullname]['cExtension'] = False
                                    package_spec.origin = self.url + "/" + path + "/__init__.py"
                                    package_spec.submodule_search_locations = [self.url + "/" + path]
                                    package_spec.has_location = True
                                    return package_spec
                            elif path + ".pyc" in mods:
                                self.modules[fullname] = {}
                                self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + pyc_mods[0], path_cache=self.path_cache, config=self.config)
                                self.modules[fullname]['filepath'] = self.url + "/" + pyc_mods[0]
                                self.modules[fullname]['package'] = False
                                self.modules[fullname]['cExtension'] = False
                                package_spec.origin = self.url + "/" + pyc_mods[0]
                                package_spec.has_location = True
                                return package_spec
                        if f"{path}/" in self.path_cache:
                            # This may be an odd package implementation which doesn't use an __init__ file (looking at you pywin32)
                            self.modules[fullname] = {}
                            self.modules[fullname]['content'] = b""
                            self.modules[fullname]['filepath'] = None
                            self.modules[fullname]['package'] = True
                            self.modules[fullname]['cExtension'] = False
                            package_spec.origin = None
                            package_spec.submodule_search_locations = [self.url + "/" + path]
                            package_spec.has_location = True
                            return package_spec
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

        def create_module(self, spec):
            """
            Description:
                Creates a module object of the requested module
            Args:
                spec: spec of module being imported
            Returns:
                module object or None if the default module creation semantics should take place
            """
            module = type(sys)(spec.name)
            try:
                filename = spec.loader_state.filename
            except AttributeError:
                pass
            else:
                if filename:
                    module.__file__ = filename
            return module

        def exec_module(self, module):
            """
            Description:
                Executes the module in its own namespace when a module is imported or reloaded
            Args:
                module: module being imported
            """
            if hasattr(module, "__cached__"):
                delattr(module, "__cached__")
            spec = module.__spec__
            name = spec.name
            import_module = self.modules[name]
            if name not in self.modules:
                raise ImportError("Failed to load module %s from %s" % (name, self.url))
            # Handle dynamic patching, if required
            if name not in self.bootcode_added:
                hooked_module = self.hook(module, self.url)
                if self._boot_code:
                    self.bootcode_added.append(name)
                    for boot_code in self._boot_code:
                        if name == hooked_module:
                            exec(boot_code, globals())
                    self._boot_code = []
            if import_module['cExtension']:
                if not hasattr(module, '__builtins__'):
                    module.__builtins__ = __builtins__
                self.path = spec.origin
                spec._set_fileattr = False
                initname = f"PyInit_{name.split('.')[-1]}"
                mod = _memimporter.import_module(name, name, initname, self._get_module_content, spec)
                mod.__spec__ = spec
                mod.__file__ = spec.origin
                mod.__loader__ = spec.loader
                mod.__package__ = spec.parent
            else:
                if self.modules[name]['filepath']:
                    self.path = module.__file__
                else:
                    self.path = f"{self.url}/{name}/"
                sys.modules[name] = module
                if module.__file__.endswith(".pyc"):
                    try:
                        decompile_content = marshal.loads(import_module['content'][16:])
                    except:
                        logging.info(f"Failed to marshal {module.__file__} with offset of 16")
                        try:
                            decompile_content = marshal.loads(import_module['content'][12:])
                        except:
                            logging.info(f"Failed to marshal {module.__file__} with offset of 12")
                            decompile_content = marshal.loads(import_module['content'][8:])
                    import_module['content'] = decompile_content
                exec(import_module['content'], module.__dict__)
            if name in self.modules:
                # release loaded module
                self.modules.pop(name)

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
        if self.path_cache and fullname not in self.excludes:
            depth = 1
            path = fullname.replace(".","/")
            while depth <= len(path.split("/")):
                if "/".join(path.split("/")[:depth]) == path:
                    mods = [mod for mod in self.path_cache if mod.startswith(path)]
                    c_mods = [mod for mod in self.path_cache if mod.startswith(path) and (mod.split("/")[depth - 1].endswith(".dll") or mod.split("/")[depth - 1].endswith(".pyd"))]
                    pyc_mods = [mod for mod in self.path_cache if mod.startswith(path) and mod.split("/")[depth - 1].endswith(".pyc")]
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
                            if path + "/__init__.py" not in self.path_cache:
                                # Let's try to update the cache
                                self.proto_handler(self.url, path=path + "/", path_cache=self.path_cache, config=self.config)
                            if path + "/__init__.py" in self.path_cache:
                                self.modules[fullname] = {}
                                self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + path + "/__init__.py", cache_update=False, path_cache=self.path_cache, config=self.config)
                                self.modules[fullname]['filepath'] = self.url + "/" + path + "/__init__.py"
                                self.modules[fullname]['package'] = True
                                self.modules[fullname]['cExtension'] = False
                                return self
                        elif path + ".pyc" in mods:
                            self.modules[fullname] = {}
                            self.modules[fullname]['content'] = self.proto_handler(self.url + "/" + pyc_mods[0], path_cache=self.path_cache, config=self.config)
                            self.modules[fullname]['filepath'] = self.url + "/" + pyc_mods[0]
                            self.modules[fullname]['package'] = False
                            self.modules[fullname]['cExtension'] = False
                            return self
                    if f"{path}/" in self.path_cache:
                        # This may be an odd package implementation which doesn't use an __init__ file (looking at you pywin32)
                        self.modules[fullname] = {}
                        self.modules[fullname]['content'] = b""
                        self.modules[fullname]['filepath'] = None
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
        if self.modules[fullname]['filepath']:
            mod.__file__ = import_module['filepath']
            mod.__path__ = "/".join(import_module['filepath'].split("/")[:-1]) + "/"
        else:
            mod.__path__ = f"{self.url}/{fullname}/"
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
            hooked_module = self.hook(mod, self.url)
            if self._boot_code:
                self.bootcode_added.append(mod.__name__)
                for boot_code in self._boot_code:
                    if mod.__name__ == hooked_module:
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
            if self.modules[fullname]['filepath']:
                self.path = mod.__file__
            else:
                self.path = f"{self.url}/{fullname}/"
            sys.modules[fullname] = mod
            if mod.__file__.endswith(".pyc"):
                try:
                    decompile_content = marshal.loads(import_module['content'][16:])
                except:
                    logging.info(f"Failed to marshal {mod.__file__} with offset of 16")
                    try:
                        decompile_content = marshal.loads(import_module['content'][12:])
                    except:
                        logging.info(f"Failed to marshal {mod.__file__} with offset of 12")
                        decompile_content = marshal.loads(import_module['content'][8:])
                import_module['content'] = decompile_content
            exec(import_module['content'], mod.__dict__)
        if fullname in self.modules:
            if mod.__name__ not in self.bootcode_added:
                # release loaded 
                self.modules.pop(fullname)
            elif 'content' in self.modules[fullname]:
                # release loaded module content
                self.modules[fullname].pop('content')
        return mod


def add_remote_source(url: str, INSECURE: bool=False, excludes: list=[], return_importer: bool=False, zip_password: bytes=None, config: dict={}):
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

def add_github(user: str, repo: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, headers: dict={}, timeout=None):
    config = {
        "user": user,
        "repo": repo,
        "git": "github",
        "type": git_type,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    add_remote_source("https://github.com", config=config)

@contextmanager
def github(user: str, repo: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, headers: dict={}, timeout=None):
    config = {
        "user": user,
        "repo": repo,
        "git": "github",
        "type": git_type,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    import_hook = add_remote_source("https://github.com", return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

def add_gitlab(url: str, group: str, project: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, ca_file: str=None, ca_data: str=None, headers: dict={}, timeout=None):
    config = {
        "group": group,
        "project": project,
        "git": "gitlab",
        "type": git_type,
        "verify": verify,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    add_remote_source(url, config=config)

@contextmanager
def gitlab(url: str, group: str, project: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, ca_file: str=None, ca_data: str=None, headers: dict={}, timeout=None):
    config = {
        "group": group,
        "project": project,
        "git": "gitlab",
        "type": git_type,
        "verify": verify,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    import_hook = add_remote_source(url, INSECURE=INSECURE, return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

def add_gitea(url: str, user: str, repo: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, ca_file: str=None, ca_data: str=None, headers: dict={}, timeout=None):
    config = {
        "user": user,
        "repo": repo,
        "git": "gitea",
        "type": git_type,
        "verify": verify,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    add_remote_source(url, INSECURE=INSECURE, config=config)

@contextmanager
def gitea(url: str, user: str, repo: str, branch: str=None, git_type: str="git", api_key: str=None, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, ca_file: str=None, ca_data: str=None, headers: dict={}, timeout=None):
    config = {
        "user": user,
        "repo": repo,
        "git": "gitea",
        "type": git_type,
        "verify": verify,
        "timeout": timeout
    }
    if branch:
        config["branch"] = branch
    if api_key:
        config["api_key"] = api_key
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    import_hook = add_remote_source(url, INSECURE=INSECURE, return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

def add_pypi(package, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, headers: dict={}, timeout=None):
    config = {
        "package": package,
        "type": "pypi",
        "verify": verify,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    url = "https://pypi.org/pypi"
    add_remote_source(url, config=config)

@contextmanager
def pypi(package, http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, headers: dict={}, timeout=None):
    config = {
        "package": package,
        "type": "pypi",
        "verify": verify,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    url = "https://pypi.org/pypi"
    import_hook = add_remote_source(url, INSECURE=INSECURE, return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

def add_dropbox(access_token: str, path: str="", http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, headers: dict={}, timeout=None):
    config = {
        "access_token": access_token,
        "type": "dropbox",
        "verify": verify,
        "proxy": proxy,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    url = "https://api.dropboxapi.com"
    if path:
        url = "/".join([url, path.lstrip("/")])
    add_remote_source(url, config=config)

@contextmanager
def dropbox(access_token: str, path: str="", http_provider: str=None, proxy: str=None, INSECURE=False, verify: bool=True, headers: dict={}, timeout=None):
    config = {
        "access_token": access_token,
        "type": "dropbox",
        "verify": verify,
        "proxy": proxy,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    url = "https://api.dropboxapi.com"
    if path:
        url = "/".join([url, path.lstrip("/")])
    import_hook = add_remote_source(url, INSECURE=INSECURE, return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

def add_s3(bucket: str=None, region: str=None, access_key: str=None, secret_key: str=None, http_provider: str=None, proxy: str=None, headers: dict={}, timeout=None):
    config = {
        "bucket": bucket,
        "region": region,
        "type": "s3",
        "access_key": access_key,
        "secret_key": secret_key,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    add_remote_source("https://amazonaws.com", config=config)

@contextmanager
def s3(bucket: str=None, region: str=None, access_key: str=None, secret_key: str=None, http_provider: str=None, proxy: str=None, headers: dict={}, timeout=None):
    config = {
        "bucket": bucket,
        "region": region,
        "type": "s3",
        "access_key": access_key,
        "secret_key": secret_key,
        "timeout": timeout
    }
    if proxy:
        config["proxy"] = proxy
    if headers:
        config["headers"] = headers
    if http_provider == "winhttp":
        config['http_provider'] = http_provider
    import_hook = add_remote_source("https://amazonaws.com", return_importer=True, config=config)
    try:
        yield
    except ImportError as e:
        raise e
    finally:
        remove_remote_source(import_hook.url)

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
