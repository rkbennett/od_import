import io
import sys
import logging
import tarfile

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
        sdists = [item.name.split("/")[0] for item in self.tar_bytes.getmembers() if not item.isdir() and len(item.name.split("/")) > 1 and item.name.split("/")[1] == "PKG-INFO"]
        self.path_cache = path_cache + [item.name + ("/" if item.isdir() else "") for item in self.tar_bytes.getmembers()]
        if sdists:
            self.sdist_path_shim = {"-".join(sdist.split("-")[:-1]): sdist for sdist in sdists if "-".join(sdist.split("-")[:-1]) not in self.path_cache}
            for package, sdist in self.sdist_path_shim.items():
                if package not in self.path_cache:
                    for cached_path in self.path_cache:
                        if cached_path.startswith(f"{sdist}/") and cached_path != f"{sdist}/":
                            self.path_cache.append(cached_path.replace(f"{sdist}/", ""))

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
        request_file = url.replace(self.url, "").lstrip("/")
        if request_file.split("/")[0] in self.sdist_path_shim:
            request_file = f"{self.sdist_path_shim[request_file.split('/')[0]]}/{request_file}"
        return self.tar_bytes.extractfile(request_file).read()
