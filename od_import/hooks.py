# -*- coding: utf-8 -*-
#
# Hooks module for od_importer.
# Inspired by cx_freeze's hooks.py, which is:
#
#    Copyright Â© 2007-2013, Anthony Tuininga.
#    Copyright Â© 2001-2006, Computronix (Canada) Ltd., Edmonton, Alberta, Canada.
#    All rights reserved.
#
import os, sys

# Exclude modules that the standard library imports (conditionally),
# but which are not present on windows.
#
# _memimporter can be excluded because it is built into the run-stub.
windows_excludes = """
_curses
_dummy_threading
_emx_link
_gestalt
_posixsubprocess
ce
clr
console
fcntl
grp
java
org
os2
posix
pwd
site
termios
vms_lib
_memimporter
""".split()

def init_finder(finder):
    # what about renamed functions, like urllib.pathname2url?
    #
    # We should use ignore() for Python 2 names so that my py2to3
    # importhook works.  For modules that are not present on Windows,
    # we should probably use excludes.append()
    finder.excludes.extend(windows_excludes)

    # python2 modules are ignored (but not excluded)
    finder.ignore("BaseHTTPServer")
    finder.ignore("ConfigParser")
    finder.ignore("IronPython")
    finder.ignore("SimpleHTTPServer")
    finder.ignore("StringIO")
    finder.ignore("__builtin__")
    finder.ignore("_winreg")
    finder.ignore("cPickle")
    finder.ignore("cStringIO")
    finder.ignore("commands")
    finder.ignore("compiler")
    finder.ignore("copy_reg")
    finder.ignore("dummy_thread")
    finder.ignore("future_builtins")
    finder.ignore("htmlentitydefs")
    finder.ignore("httplib")
    finder.ignore("md5")
    finder.ignore("new")
    finder.ignore("thread")
    finder.ignore("unittest2")
    finder.ignore("urllib2")
    finder.ignore("urlparse")

def hook_clr_loader(finder, module, path, proto_handler, proto_config):
    finder.add_bootcode(f"""
import os
import sys
import importlib
import pyclrhost
import {proto_handler}
import {proto_config}
from cffi import FFI
ffi = FFI()

if '{module.__name__}.ffi' not in sys.modules:
    import {module.__name__}.ffi
    def override_load_netfx():
        if sys.platform != "win32":
            raise RuntimeError(".NET Framework is only supported on Windows")

        dirname = '{path}/{module.__name__}/ffi/dlls'
        if sys.maxsize > 2**32:
            arch = "amd64"
        else:
            arch = "x86"

        path = dirname + "/" + arch + "/ClrLoader.dll"
        dll = {proto_handler}(path, cache_update=False, config={proto_config})
        if os.path.isdir(os.environ['SYSTEMROOT'] + "\\Microsoft.NET\\Framework"):
            net_path = os.environ['SYSTEMROOT'] + "\\Microsoft.NET\\Framework"
            runtime_version = [ name for name in os.listdir(net_path) if os.path.isdir(os.path.join(net_path, name)) ][-1]
        else:
            runtime_version = 'v4.0.30319'
        pyclrhost.dotnet(runtime_version, dll)
        pyclrhost.pyclr_initialize()
        return pyclrhost

    sys.modules['{module.__name__}.ffi'].load_netfx = override_load_netfx


    import {module.__name__}.netfx
    from {module.__name__}.types import StrOrPath
    from pathlib import Path
    from typing import Optional
    initialize = sys.modules['{module.__name__}.netfx'].initialize

    def override___init__(self, domain: Optional[str] = None, config_file: Optional[Path] = None):
        initialize()
        _FW = sys.modules['clr_loader.netfx']._FW
        if config_file is not None:
            config_file_s = str(config_file)
        else:
            config_file_s = b""

        self._domain_name = domain
        self._config_file = config_file
        self._domain = _FW.pyclr_create_appdomain(domain or "", config_file_s.decode())

    sys.modules['{module.__name__}.netfx'].NetFx.__init__ = override___init__

    def override__get_callable(self, assembly_path: StrOrPath, typename: str, function: str):
        path = assembly_path.replace('\\\\','/')
        if "://" not in path:
            path = path.replace(":/","://")
        dll = {proto_handler}(path, cache_update=False, config={proto_config})
        _FW = sys.modules['clr_loader.netfx']._FW
        intPtr = _FW.pyclr_get_function(
            self._domain,
            typename,
            function,
            dll
        )
        func = ffi.cast("int(*)(void *, int)",intPtr)
        return func

    sys.modules['{module.__name__}.netfx'].NetFx._get_callable = override__get_callable

""")

def hook_Cryptodome(finder, module, path, proto_handler, proto_config):
    """pycryptodomex distributes the same package as pycryptodome under a different package name"""
    hook_Crypto(finder, module, path, proto_handler, proto_config)

def hook_Crypto(finder, module, path, proto_handler, proto_config):
    """pycryptodome includes compiled libraries as if they were Python C extensions (as .pyd files).
    However, they are not, as they cannot be imported by Python. Hence, those files should be treated
    as .dll files. Furthermore, pycryptodome needs to be patched to import those libraries from an external
    path, as their import mechanism will not work from the zip file nor from the executable."""
    # copy all the "pyd" files from pycryptodome to the bundle directory with the correct folder structure
    crypto_path = os.path.dirname(module.__loader__.path)
    from pathlib import Path
    for path in Path(crypto_path).rglob('*.pyd'):
        finder.add_libfile(str(path.relative_to(os.path.dirname(crypto_path))), path)

    # patch pycryptodome to look for its "pyd" files in the bundle directory
    finder.add_bootcode(f"""
import os
import sys
import ctypes
import importlib
import {proto_handler}
import {proto_config}
from cffi import FFI
ffi = FFI()

if '{module.__name__}.Util._file_system' not in sys.modules:
    import {module.__name__}.Util._file_system
    def override_filename(dir_comps, filename):
        if dir_comps[0] != '{module.__name__}':
            raise ValueError("Only available for modules under '{module.__name__}'")

        dir_comps = list(dir_comps) + [filename]
        return ('{path}' + '/' + '/'.join(dir_comps))

    sys.modules['{module.__name__}.Util._file_system'].pycryptodome_filename = override_filename

pycryptodome_filename = sys.modules['{module.__name__}.Util._file_system'].pycryptodome_filename

if '{module.__name__}.Util._raw_api' not in sys.modules:
    global kernel32
    kernel32 = ctypes.windll.kernel32
    import {module.__name__}.Util._raw_api
    def override_raw_lib(name, cdecl):
        split = name.split(".")
        dir_comps, basename = split[:-1], split[-1]
        attempts = []
        try:
            filename = basename
            full_name = pycryptodome_filename(dir_comps, filename)
            try:
                pyd = {proto_handler}(f'{{full_name}}.pyd', path_cache=[None],cache_update=False, config={proto_config})
                vptrint = _memimporter.dlopen(pyd,0)
                lib = ffi.dlopen(ffi.cast("void *",vptrint))
                ffi.cdef(cdecl)
                return lib
            except Exception as e:
                print(e)
                attempts.append("Not found '%s'" % filename)
        except OSError as exp:
            attempts.append("Cannot load '%s': %s" % (filename, str(exp)))
        raise OSError("Cannot load native module '%s': %s" % (name, ", ".join(attempts)))


    sys.modules['{module.__name__}.Util._raw_api'].load_pycryptodome_raw_lib = override_raw_lib
""")