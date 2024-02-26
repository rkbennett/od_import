import io
import sys
import json
import time
import logging
import zipfile
import tarfile
import operator
import platform

tar_io = io.BytesIO()
tar_bytes = tarfile.open(fileobj=tar_io, mode='w:gz')

def py_compare(version_operators):
    py_vers = tuple(map(int, platform.python_version().split(".")))
    for operator in version_operators:
        splat = True if "*" in operator else False
        operator_version = operator.split("=")[-1].split(">")[-1].split("<")[-1]
        operator = operator.replace(operator_version, "")
        operator_version = tuple(map(int, operator_version.replace(".*","").split(".")))
        if splat:
            temp_vers = py_vers[:len(operator_version)]
        else:
            temp_vers = py_vers
        if not eval(f"{str(temp_vers)}{operator}{str(operator_version)}"):
            return False
    return True

def fetch_py_compatability(package):
    if isinstance(package, dict):
        if package['requires_python']:
            py_reqs = package['requires_python'].split(",")
        else:
            py_reqs = []
        try:
            if py_compare(py_reqs):
                return package
        except Exception as e:
            logging.warn(e)
            return None
    return None

def match_distro(package):
    tarball = None
    sys_os = platform.system()
    sys_arch = platform.machine()
    py_version_int = int(f"{sys.version_info[0]}{sys.version_info[1]}")
    for distro in package:
        if distro['packagetype'] == "sdist":
            distro['cpy_vers'] = 0
        else:
            cpy_vers = distro['filename'].split("-")[2].lstrip("cp").lstrip("y")
            if len(cpy_vers) == 2:
                cpy_vers = cpy_vers.replace(cpy_vers[0], f"{cpy_vers[0]}0")
            distro['cpy_vers'] = int(cpy_vers)
    package = sorted(package, key=operator.itemgetter('cpy_vers'), reverse=True)
    for distro in package:
        if distro['packagetype'] == "sdist":
            tarball = distro['url']
        else:
            if sys_os == "Windows":
                os = "win"
            elif sys_os == "Linux":
                os = "manylinux"
            if sys_arch == "AMD64":
                arch = "64"
            elif sys_arch == "i686":
                arch = "i686"
            else:
                arch = "32"
            file_distro = distro['filename'].split("-")[-1]
            cp_version = int(distro['filename'].split("-")[2].lstrip("cp").lstrip("y"))
            if ((os in file_distro and arch in file_distro) or file_distro.startswith("any")) and py_version_int >= cp_version:
                return distro['url']
    return tarball

def fetch_release(url, package, config, _core):
    if isinstance(package, str) or (isinstance(package, dict) and (not 'release' in package or not package['release'])):
        release = None
        if isinstance(package, str):
            url += f"/{package}/json"
        elif isinstance(package, dict):
            url += f"/{package['name']}/json"
    elif 'release' in package:
        release = package['release']
        url += f"/{package['name']}/json"
    resp = _core.request(url, config=config).read()
    try:
        resp_json = json.loads(resp)
        releases = list(resp_json['releases'].keys())
        if release and release in releases:
            release_data = resp_json['releases'][release]
            if fetch_py_compatability(release_data[0]):
                compatable_package = release_data
            else:
                raise ImportError(f"Defined release isn't compatible with python version {platform.python_version()}")
            package_content = _core.request(match_distro(compatable_package), config=config).read()
            return package_content
        elif not release:
            releases.reverse()
            for release in releases:
                if fetch_py_compatability(resp_json['releases'][release][0]):
                    compatable_package = resp_json['releases'][release]
                    break
            if compatable_package:
                package_content = _core.request(match_distro(compatable_package), config=config).read()
                return package_content
            else:
                raise ImportError(f"Failed to locate compatible release with python version {platform.python_version()}")
        else:
            return b""
    except Exception as e:
        logging.info(e)
        return b""

def extract_zip_to_archive(package, pkg_metadata):
    zip_io = io.BytesIO(package)
    zip_bytes = zipfile.ZipFile(zip_io, mode="r")
    if isinstance(pkg_metadata, str):
        pkg_name = pkg_metadata
    elif isinstance(pkg_metadata, dict):
        pkg_name = pkg_metadata['name']
    files = [item for item in zip_bytes.infolist() if ".dist-info/" not in item.filename]
    directories = set(["/".join(item.filename.split("/")[:-1]) for item in files])
    for directory in directories:
        tar_info = tarfile.TarInfo(directory)
        tar_info.type = tarfile.DIRTYPE
        tar_bytes.addfile(tar_info)
    for item in files:
        tar_info = tarfile.TarInfo(name=item.filename)
        tar_info.size = item.file_size
        tar_info.mtime = time.mktime(tuple(item.date_time) +
                (-1, -1, -1))
        tar_bytes.addfile(tarinfo=tar_info, fileobj=zip_bytes.open(item.filename))
    zip_bytes.close()

def extract_tar_to_archive(package, pkg_metadata):
    tar_read_io = io.BytesIO(package)
    tar_read_bytes = tarfile.open(fileobj=tar_read_io, mode='r:*')
    if isinstance(pkg_metadata, str):
        pkg_name = pkg_metadata
    elif isinstance(pkg_metadata, dict):
        pkg_name = pkg_metadata['name']
    files = [item for item in tar_read_bytes.getmembers() if ".dist-info/" not in item.name]
    for item in files:
        tar_info = tarfile.TarInfo(item.name)
        if item.isdir:
            tar_info.type = tarfile.DIRTYPE
        tar_info.size = item.size
        tar_info.mtime = item.mtime
        if item.isdir:
            tar_bytes.addfile(tar_info)
        else:
            tar_bytes.addfile(tarinfo=tar_info, fileobj=tar_read_bytes.extractfile(item.name))
    tar_read_bytes.close()

########################## Protocol Handlers #########################

def pypi(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'package' not in config.__dict__:
        raise KeyError("Missing required key 'package'...")
    if 'release' not in config.__dict__:
        config.release = None
    if isinstance(config.package, list):
        for package in config.package:
            package_content = fetch_release(url, package, config, _core)
            if package_content.startswith(b'\x50\x4b\x03\x04'):
                extract_zip_to_archive(package_content, package)
            elif package_content.startswith(b'\x1f\x8b') or (len(package_content) > 260 and package_content[257:].startswith(b"ustar")):
                extract_tar_to_archive(package_content, package)
    else:
        package_content = fetch_release(url, config.package, config, _core)
        if package_content.startswith(b'\x50\x4b\x03\x04'):
            extract_zip_to_archive(package_content, config.package)
        elif package_content.startswith(b'\x1f\x8b') or (len(package_content) > 260 and package_content[257:].startswith(b"ustar")):
            logging.warn("Tar packages are currently not supported")
            return b""
            extract_tar_to_archive(package_content, config.package)
    tar_bytes.close()
    tar_io.seek(0)
    resp = tar_io.read()
    return resp
