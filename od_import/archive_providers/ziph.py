import io
import os
import sys
import logging
import zipfile

class ziph(object):

    def __init__(self, data: bytes, url_base: str, path_cache: list=[], config: None=None, pwd: bytes=None):
        """
        Description:
            Handles loading of zip archive and updates the import hook path cache
        Args:
            data: bytes of archive
            url_base: unused in this module
            path_cache: list of paths the import hook tracks
            config: unused in this module
            pwd: the password used to open the archive
        """
        self.pwd = pwd
        self.url = url_base
        zip_io = io.BytesIO(data)
        self.zip_bytes = zipfile.ZipFile(zip_io)
        self.path_cache = path_cache
        for item in self.zip_bytes.filelist:
            self.path_cache.append(item.filename)
            path = os.path.dirname(item.filename) + "/"
            if path not in self.path_cache:
                self.path_cache.append(path)
    
    def extractor(self, url: str, path: str="", path_cache: list=[], cache_update: bool=False, config: None=None, pwd: bytes=None) -> bytes:
        """
        Description:
            Handles requests for content from a zip archive object
        Args:
            url: requested path of content with full url
            path: subpath to subpackage or nested module
            path_cache: unused in this function
            cache_update: unused in this module
            config: unused in this module
            pwd: the password used to open the archive
        return:
            bytes of file content or empty bytes object
        """
        if path in self.path_cache:
            return b""
        return self.zip_bytes.open(url.replace(self.url, "").lstrip("/"), 'r', pwd=self.pwd).read()
