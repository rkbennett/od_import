import io
import os
import sys
import ssl
import json
import time
import pathlib
import hashlib
import logging
import zipfile
import tarfile
import operator
import platform
import functools
import importlib
import email.message
from typing import Iterable, Tuple, Optional, Mapping, Iterator, Collection, cast
from pip._internal import main as pipmain
import pip._internal.req.req_install
import pip._internal.network.download
import pip._internal.operations.prepare
from pip._internal.operations.build.build_tracker import BuildTracker
from pip._internal.exceptions import InvalidWheel, UnsupportedWheel
from pip._internal.models.link import Link
from pip._internal.utils.hashes import Hashes
from pip._internal.operations.prepare import File
from pip._internal.network.session import PipSession
from pip._internal.models.direct_url import ArchiveInfo
from pip._internal.metadata.base import InfoPath, Wheel, DistributionVersion, BaseEntryPoint
from pip._internal.utils.wheel import parse_wheel, read_wheel_metadata_file
from pip._vendor.packaging.utils import canonicalize_name, NormalizedName
from pip._internal.exceptions import NetworkConnectionError
from pip._internal.req.req_install import InstallRequirement
from pip._internal.utils.direct_url_helpers import direct_url_from_link
from pip._internal.metadata import BaseDistribution, get_metadata_distribution, FilesystemWheel
from pip._internal.utils.temp_dir import TempDirectory
from pip._internal.index.package_finder import PackageFinder
from pip._vendor.packaging.requirements import Requirement
import pip._internal.metadata.importlib._dists
from pip._internal.metadata.importlib._compat import BasePath
from pip._internal.distributions.base import AbstractDistribution
from pip._internal.distributions.sdist import SourceDistribution
from pip._internal.req.req_install import InstallRequirement
from pip._vendor.packaging.version import parse as parse_version

wheel_dict = {}
tar_io = io.BytesIO()
tar_bytes = tarfile.open(fileobj=tar_io, mode='w:gz')
logger = logging.getLogger(__name__)
unpack_url = sys.modules['pip._internal.operations.prepare'].unpack_url
_check_download_dir = pip._internal.operations.prepare._check_download_dir
_prepare_download = pip._internal.network.download._prepare_download
_http_get_download = pip._internal.network.download._http_get_download
_get_http_response_filename = pip._internal.network.download._get_http_response_filename

class OverloadDistribution(BaseDistribution):
    def __init__(
        self,
        dist: importlib.metadata.Distribution,
        info_location: Optional[BasePath],
        installed_location: Optional[BasePath],
    ) -> None:
        self._dist = dist
        self._info_location = info_location
        self._installed_location = installed_location
    
    @classmethod
    def from_directory(cls, directory: str) -> BaseDistribution:
        info_location = pathlib.Path(directory)
        dist = importlib.metadata.Distribution.at(info_location)
        return cls(dist, info_location, info_location.parent)
    
    @classmethod
    def from_metadata_file_contents(
        cls,
        metadata_contents: bytes,
        filename: str,
        project_name: str,
    ) -> BaseDistribution:
        temp_dir = pathlib.Path(
            TempDirectory(kind="metadata", globally_managed=True).path
        )
        metadata_path = temp_dir / "METADATA"
        metadata_path.write_bytes(metadata_contents)
        dist = importlib.metadata.Distribution.at(metadata_path.parent)
        return cls(dist, metadata_path.parent, None)
    
    @classmethod
    def from_wheel(cls, wheel: Wheel, name: str) -> BaseDistribution:
        try:
            with wheel.as_zipfile() as zf:
                dist = OverloadWheelDist.from_zipfile(zf, name, wheel.location)
        except zipfile.BadZipFile as e:
            raise InvalidWheel(wheel.location, name) from e
        except UnsupportedWheel as e:
            raise UnsupportedWheel(f"{name} has an invalid wheel, {e}")
        return cls(dist, dist.info_location, wheel.location)
    
    @property
    def location(self) -> Optional[str]:
        if self._info_location is None:
            return None
        return str(self._info_location.parent)
    
    @property
    def info_location(self) -> Optional[str]:
        if self._info_location is None:
            return None
        return str(self._info_location)
    
    @property
    def installed_location(self) -> Optional[str]:
        if self._installed_location is None:
            return None
        return normalize_path(str(self._installed_location))
    
    def _get_dist_name_from_location(self) -> Optional[str]:
        """Try to get the name from the metadata directory name.
        
        This is much faster than reading metadata.
        """
        if self._info_location is None:
            return None
        stem, suffix = os.path.splitext(self._info_location.name)
        if suffix not in (".dist-info", ".egg-info"):
            return None
        return stem.split("-", 1)[0]
    
    @property
    def canonical_name(self) -> NormalizedName:
        name = self._get_dist_name_from_location() or get_dist_name(self._dist)
        return canonicalize_name(name)
    
    @property
    def version(self) -> DistributionVersion:
        return parse_version(self._dist.version)
    
    def is_file(self, path: InfoPath) -> bool:
        return self._dist.read_text(str(path)) is not None
    
    def iter_distutils_script_names(self) -> Iterator[str]:
        if not isinstance(self._info_location, pathlib.Path):
            return
        for child in self._info_location.joinpath("scripts").iterdir():
            yield child.name
    
    def read_text(self, path: InfoPath) -> str:
        content = self._dist.read_text(str(path))
        if content is None:
            raise FileNotFoundError(path)
        return content
    
    def iter_entry_points(self) -> Iterable[BaseEntryPoint]:
        return self._dist.entry_points
    
    def _metadata_impl(self) -> email.message.Message:
        return cast(email.message.Message, self._dist.metadata)
    
    def iter_provided_extras(self) -> Iterable[str]:
        return (
            safe_extra(extra) for extra in self.metadata.get_all("Provides-Extra", [])
        )
    
    def iter_dependencies(self, extras: Collection[str] = ()) -> Iterable[Requirement]:
        contexts: Sequence[Dict[str, str]] = [{"extra": safe_extra(e)} for e in extras]
        for req_string in self.metadata.get_all("Requires-Dist", []):
            req = Requirement(req_string)
            if not req.marker:
                yield req
            elif not extras and req.marker.evaluate({"extra": ""}):
                yield req
            elif any(req.marker.evaluate(context) for context in contexts):
                yield req

sys.modules['pip._internal.metadata.importlib._dists'].Distribution = OverloadDistribution

class OverloadWheelDist(importlib.metadata.Distribution):
    """An ``importlib.metadata.Distribution`` read from a wheel.

    Although ``importlib.metadata.PathDistribution`` accepts ``zipfile.Path``,
    its implementation is too "lazy" for pip's needs (we can't keep the ZipFile
    handle open for the entire lifetime of the distribution object).

    This implementation eagerly reads the entire metadata directory into the
    memory instead, and operates from that.
    """
    
    def __init__(
        self,
        files: Mapping[pathlib.PurePosixPath, bytes],
        info_location: pathlib.PurePosixPath,
    ) -> None:
        self._files = files
        self.info_location = info_location
    
    @classmethod
    def from_zipfile(
        cls,
        zf: zipfile.ZipFile,
        name: str,
        location: str,
    ) -> "WheelDistribution":
        info_dir, _ = parse_wheel(zf, name)
        paths = (
            (name, pathlib.PurePosixPath(name.split("/", 1)[-1]))
            for name in zf.namelist()
            if name.startswith(f"{info_dir}/")
        )
        files = {
            relpath: read_wheel_metadata_file(zf, fullpath)
            for fullpath, relpath in paths
        }
        return cls(files, info_dir)
    
    def iterdir(self, path: InfoPath) -> Iterator[pathlib.PurePosixPath]:
        if pathlib.PurePosixPath(str(path)) in self._files:
            return iter(self._files)
        raise FileNotFoundError(path)
    
    def read_text(self, filename: str) -> Optional[str]:
        try:
            data = self._files[pathlib.PurePosixPath(filename)]
        except KeyError:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            wheel = self.info_location.parent
            error = f"Error decoding metadata for {wheel}: {e} in {filename} file"
            raise UnsupportedWheel(error)
        return text

sys.modules['pip._internal.metadata.importlib._dists'].WheelDistribution = OverloadWheelDist

class OverloadDownloader:
    def __init__(
        self,
        session: PipSession,
        progress_bar: str,
    ) -> None:
        self._session = session
        self._progress_bar = progress_bar
    
    def __call__(self, link: Link, location: io.BytesIO) -> Tuple[str, str]:
        """Download the file given by link into location."""
        try:
            resp = _http_get_download(self._session, link)
        except NetworkConnectionError as e:
            assert e.response is not None
            logger.critical(
                "HTTP error %s while getting %s", e.response.status_code, link
            )
            raise
        filename = _get_http_response_filename(resp, link)
        
        chunks = _prepare_download(resp, link, self._progress_bar)
        for chunk in chunks:
            location.write(chunk)
        content_type = resp.headers.get("Content-Type", "")
        return location, content_type

sys.modules['pip._internal.operations.prepare'].Downloader = sys.modules['pip._internal.network.download'].Downloader = OverloadDownloader

class OverloadBatchDownloader:
    def __init__(
        self,
        session: PipSession,
        progress_bar: str,
    ) -> None:
        self._session = session
        self._progress_bar = progress_bar
    
    def __call__(
        self, links: Iterable[Link], location: io.BytesIO
    ) -> Iterable[Tuple[Link, Tuple[str, str]]]:
        """Download the files given by links into location."""
        for link in links:
            wheel_dict[link.filename] = io.BytesIO()
            try:
                resp = _http_get_download(self._session, link)
            except NetworkConnectionError as e:
                assert e.response is not None
                logger.critical(
                    "HTTP error %s while getting %s",
                    e.response.status_code,
                    link,
                )
                raise
            filename = _get_http_response_filename(resp, link)
            filepath = os.path.join("location", filename)
            
            chunks = _prepare_download(resp, link, self._progress_bar)
            for chunk in chunks:
                wheel_dict[link.filename].write(chunk)
            content_type = resp.headers.get("Content-Type", "")
            yield link, (filepath, content_type)

sys.modules['pip._internal.operations.prepare'].BatchDownloader = sys.modules['pip._internal.network.download'].BatchDownloader = OverloadBatchDownloader

def overload_check_download_dir(
    link: Link,
    download_dir,
    hashes: Optional[Hashes],
    warn_on_hash_mismatch: bool = True,
) -> Optional[str]:
    """Check download_dir for previously downloaded file with correct hash
    If a correct file is found return its path else None
    """
    
    if isinstance(download_dir, str) or not download_dir.getbuffer().nbytes:
        return None
    
    logger.info("File was already downloaded")
    if hashes:
        try:
            hashes.check_against_file(download_dir)
        except HashMismatch:
            if warn_on_hash_mismatch:
                logger.warning(
                    "Previously-downloaded file has bad hash. Re-downloading."
                )
            return None
    return download_path

def overload_get_http_url(
    link: Link,
    download: OverloadDownloader,
    download_dir: Optional[str] = None,
    hashes: Optional[Hashes] = None,
) -> io.BytesIO:
    download = OverloadDownloader(download._session, download._progress_bar)
    download_dir = io.BytesIO()
    already_downloaded_path = None
    if download_dir.getbuffer().nbytes:
        already_downloaded_path = _check_download_dir(link, download_dir, hashes)
    
    if already_downloaded_path:
        from_path = already_downloaded_path
        content_type = None
    else:
        from_path, content_type = download(link, download_dir)
        download_dir.seek(0)
        if hashes:
            hashes.check_against_file(download_dir)
    
    return download_dir

def overload_fetch_metadata_using_link_data_attr(
        self,
        req: InstallRequirement,
    ) -> Optional[BaseDistribution]:
    """Fetch metadata from the data-dist-info-metadata attribute, if possible."""
    metadata_link = req.link.metadata_link()
    if metadata_link is None:
        return None
    assert req.req is not None
    logger.info(
        "Obtaining dependency information for %s from %s",
        req.req,
        metadata_link,
    )
    metadata_file = overload_get_http_url(
        metadata_link,
        self._download,
        hashes=metadata_link.as_hashes(),
    )
    metadata_file.seek(0)
    metadata_contents = metadata_file.read()
    metadata_dist = get_metadata_distribution(
        metadata_contents,
        req.link.filename,
        req.req.name,
    )
    if canonicalize_name(metadata_dist.raw_name) != canonicalize_name(req.req.name):
        raise MetadataInconsistent(
            req, "Name", req.req.name, metadata_dist.raw_name
        )
    return metadata_dist

def overload_make_distribution_for_install_requirement(
    install_req: InstallRequirement,
) -> AbstractDistribution:
    """Returns a Distribution for the given InstallRequirement"""
    if install_req.editable:
        return SourceDistribution(install_req)
    
    if install_req.is_wheel:
        return OverloadWheelDistribution(install_req)
    
    return SourceDistribution(install_req)

sys.modules['pip._internal.distributions'].make_distribution_for_install_requirement = overload_make_distribution_for_install_requirement

def overload_get_prepared_distribution(
    req: InstallRequirement,
    build_tracker: BuildTracker,
    finder: PackageFinder,
    build_isolation: bool,
    check_build_deps: bool,
) -> BaseDistribution:
    """Prepare a distribution for installation."""
    abstract_dist = overload_make_distribution_for_install_requirement(req)
    with build_tracker.track(req):
        abstract_dist.prepare_distribution_metadata(
            finder, build_isolation, check_build_deps
        )
    return abstract_dist.get_metadata_distribution()

_get_prepared_distribution = sys.modules['pip._internal.operations.prepare']._get_prepared_distribution = overload_get_prepared_distribution

def overload_prepare_linked_requirement(
        self, req: InstallRequirement, parallel_builds: bool
    ) -> BaseDistribution:
    assert req.link
    link = req.link
    hashes = self._get_linked_req_hashes(req)
    
    if hashes and req.is_wheel_from_cache:
        assert req.download_info is not None
        assert link.is_wheel
        assert link.is_file
        if (
            isinstance(req.download_info.info, ArchiveInfo)
            and req.download_info.info.hashes
            and hashes.has_one_of(req.download_info.info.hashes)
        ):
            hashes = None
        else:
            logger.warning(
                "The hashes of the source archive found in cache entry "
                "don't match, ignoring cached built wheel "
                "and re-downloading source."
            )
            req.link = req.cached_wheel_source_link
            link = req.link
    
    self._ensure_link_req_src_dir(req, parallel_builds)
    if link.is_existing_dir():
        local_file = None
    elif link.url:
        try:
            local_file = unpack_url(
                link,
                req.source_dir,
                self._download,
                self.verbosity,
                self.download_dir,
                hashes,
            )
        except NetworkConnectionError as exc:
            raise InstallationError(
                "Could not install requirement {} because of HTTP "
                "error {} for URL {}".format(req, exc, link)
            )
    
    if req.download_info is None:
        assert not req.editable
        req.download_info = direct_url_from_link(link, req.source_dir)
        if (
            isinstance(req.download_info.info, ArchiveInfo)
            and not req.download_info.info.hashes
            and local_file
        ):
            hash = hash_file(local_file.path)[0].hexdigest()
            req.download_info.info.hash = f"sha256={hash}"
    
    local_file.seek(0)
    if local_file.getbuffer().nbytes:
        req.local_file_path = local_file
    dist = overload_get_prepared_distribution(
        req,
        self.build_tracker,
        self.finder,
        self.build_isolation,
        self.check_build_deps,
    )
    return dist

Backend = pip._internal.metadata.Backend
_should_use_importlib_metadata = pip._internal.metadata._should_use_importlib_metadata

@functools.lru_cache(maxsize=None)
def overload_select_backend() -> Backend:
    if _should_use_importlib_metadata():
        importlib = pip._internal.metadata.importlib
        return cast(Backend, importlib)
    pkg_resources = pip._internal.metadata.pkg_resources
    
    return cast(Backend, pkg_resources)

def overload_get_wheel_distribution(wheel: Wheel, canonical_name: str) -> BaseDistribution:
    """Get the representation of the specified wheel's distribution metadata.
    
    This returns a Distribution instance from the chosen backend based on
    the given wheel's ``.dist-info`` directory.
    
    :param canonical_name: Normalized project name of the given wheel.
    """
    backend = overload_select_backend()
    backend.Distribution = cast(backend.Distribution, OverloadDistribution)
    return backend.Distribution.from_wheel(wheel, canonical_name)

def overload_get_dist(self) -> BaseDistribution:
    if self.metadata_directory:
        return get_directory_distribution(self.metadata_directory)
    elif self.local_file_path and self.is_wheel:
        dist = overload_get_wheel_distribution(
            FilesystemWheel(self.local_file_path), canonicalize_name(self.name)
        )
        return dist
    raise AssertionError(
        f"InstallRequirement {self} has no metadata directory and no wheel: "
        f"can't make a distribution."
    )

InstallRequirement.get_dist = sys.modules['pip._internal.req.req_install'].InstallRequirement.get_dist = overload_get_dist

class OverloadWheelDistribution(AbstractDistribution):
    """Represents a wheel distribution.

    This does not need any preparation as wheels can be directly unpacked.
    """
    
    def get_metadata_distribution(self) -> BaseDistribution:
        """Loads the metadata from the wheel file into memory and returns a
        Distribution that uses it, not relying on the wheel file or
        requirement.
        """
        assert self.req.local_file_path, "Set as part of preparation during download"
        assert self.req.name, "Wheels are never unnamed"
        wheel = FilesystemWheel(self.req.local_file_path)
        return overload_get_wheel_distribution(wheel, canonicalize_name(self.req.name))
    
    def prepare_distribution_metadata(
        self,
        finder: PackageFinder,
        build_isolation: bool,
        check_build_deps: bool,
    ) -> None:
        pass

def overload_save_linked_requirement(self, req: InstallRequirement) -> None:
    assert self.download_dir is not None
    assert req.link is not None
    link = req.link
    if link.is_vcs or (link.is_existing_dir() and req.editable):
        req.archive(self.download_dir)
        return
    if link.is_existing_dir():
        logger.debug(
            "Not copying link to destination directory "
            "since it is a directory: %s",
            link,
        )
        return
    if req.local_file_path is None:
        return
    
    download_location = os.path.join(self.download_dir, link.filename)
    if req.local_file_path.getbuffer().nbytes:
        logger.info("Saved %s", req.name)

def overload_complete_partial_requirements(
    self,
    partially_downloaded_reqs: Iterable[InstallRequirement],
    parallel_builds: bool = False,
) -> None:
    """Download any requirements which were only fetched by metadata."""
    temp_dir = "."
    
    links_to_fully_download: Dict[Link, InstallRequirement] = {}
    for req in partially_downloaded_reqs:
        assert req.link
        links_to_fully_download[req.link] = req
    batch_download = self._batch_download(
        links_to_fully_download.keys(),
        temp_dir,
    )
    for link, (filepath, _) in batch_download:
        logger.debug("Downloading link %s to %s", link, filepath)
        req = links_to_fully_download[link]
        req.local_file_path = filepath
        if req.is_wheel:
            self._downloaded[req.link.url] = filepath
    for req in partially_downloaded_reqs:
        self._prepare_linked_requirement(req, parallel_builds)

sys.modules['pip._internal.operations.prepare'].RequirementPreparer._complete_partial_requirements = overload_complete_partial_requirements
sys.modules['pip._internal.operations.prepare'].RequirementPreparer.save_linked_requirement = overload_save_linked_requirement
sys.modules['pip._internal.distributions.wheel'].WheelDistribution = OverloadWheelDistribution
sys.modules['pip._internal.metadata'].select_backend = overload_select_backend
sys.modules['pip._internal.metadata'].get_wheel_distribution = overload_get_wheel_distribution
sys.modules['pip._internal.operations.prepare']._check_download_dir = overload_check_download_dir
sys.modules['pip._internal.operations.prepare'].get_http_url = overload_get_http_url
sys.modules['pip._internal.operations.prepare'].RequirementPreparer._fetch_metadata_using_link_data_attr = overload_fetch_metadata_using_link_data_attr
sys.modules['pip._internal.operations.prepare'].RequirementPreparer._prepare_linked_requirement = overload_prepare_linked_requirement

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

def pip_handler(url, path="", path_cache: list=[], cache_update: bool=True, config: object=None) -> bytes:
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
    if 'package' not in config.__dict__:
        raise KeyError("Missing required key 'package'...")
    if isinstance(config.package, list):
        for package in config.package:
            pipmain(["download", "--prefer-binary", package, "--dest=."])
    else:
        pipmain(["download", "--prefer-binary", package, "--dest=."])
    for pkg in wheel_dict.keys():
        wheel_dict[pkg].seek(0)
        package_content = wheel_dict[pkg].read()
        if package_content.startswith(b'\x50\x4b\x03\x04'):
            extract_zip_to_archive(package_content, package)
        elif package_content.startswith(b'\x1f\x8b') or (len(package_content) > 260 and package_content[257:].startswith(b"ustar")):
            extract_tar_to_archive(package_content, package)
    tar_bytes.close()
    tar_io.seek(0)
    resp = tar_io.read()
    return resp
