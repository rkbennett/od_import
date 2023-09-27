# od_import (off-disk import)

_Remote_, _in-memory_ Python _package/module_ importing **via HTTP/S, FTP, or SMB**

## **Compatible with Python<3.12**

Inspired by [`httpimport`](https://github.com/operatorequals/httpimport).

`od_import` enables Python packages and modules to be imported within a Python interpreter's process memory via **remote `URIs`**

## Features

**Able to import packages with c extensions! (Windows only -- with _memimporter)**\
**Able to import packages via HTTP/S, SMB, or FTP**\
**Leverages path caching to avoid noisy bruteforcing (404s)**\
**Written in modular way to allow for expanding supported protocols**\
**Supports dynamic function patching to support packages with complex requirements**\
**Only imports dependencies as required (for example, won't load smb dependencies unless smb handler is used)**

## Basic Usage

### Permanently add od_import to import hooks

```python
od_import.add_remote_source('http://my-packages.local/site-packages', INSECURE=True)
import package
```

### Load package/module via HTTP/S location

```python
with od_import.remote_source('http://my-packages.local/site-packages', INSECURE=True):
  import package
```

### Load package/module via FTP location

```python
with od_import.remote_source('ftp://my-packages.local/site-packages', INSECURE=True):
  import ftp_package
```

### Load package/module via SMB location with configs

```python
config = {"user":"rkbennett","password":"1234567"}
with od_import.remote_source('smb://my-packages.local/site-packages', INSECURE=True, config=config):
  import smb_package
```

### Load Python packages from archives served over HTTP/S, FTP, or SMB

**_No files touch disk during import_**

```python
with od_import.remote_source('https://my-packages.local/package.zip'):
  import zip_package
```

### Load Python packages from password protected zip archives served over HTTP/S, FTP, or SMB

**_No files touch disk during import_**

```python
with od_import.remote_source('https://my-packages.local/package.zip', zip_password=b"SuperSecretPassword"):
  import zip_package
```

### Importing modules/packages with c extensions (uses [`py3memimporter`](https://github.com/rkbennett/py3memimporter))

```python
import py3memimporter
import od_import
od_import.add_remote_source('http://my-packages.local/site-packages', INSECURE=True)
import psutil
```

## Configs

Configs are a dict of attributes associated with the remote source for packages/modules

### Config Attributes

#### HTTP/S

* `user`
* `password`
* `headers` (dictionary of headers for requests, user-agent defaults to Python-urllib/3.x)
* `proxy` (Currently supports unauthenticated only)

#### SMB

* `port` (defaults to 445)
* `user` (defaults to guest)
* `password` (defaults to guest)
* `proxy` (Not currently used)
* `client` (what the client wants to be called, defaults to localhost)
* `nbname` (netbios name for remote source, defaults to hostname from URL)
* `smb2` (enables smb2 support, defaults to True)

#### FTP

* `port` (defaults to 21)
* `user` (defaults to anonymous)
* `password` (defaults to "")
* `proxy` (Not currently used)

## INSECURE

This is a boolean arg that is supplied to the hook constructor, which enables the use of insecure protocols (http, smb, ftp)

## Zip passwords

If you are importing from a zip which requires a password, you must provide the zip_password keyword arg to the hook constructor

## TODO

### HTTP handler

* `certificate verify disable`
* `custom certificate support`
* `github helper`
* `gitlab helper`
* `pypi helper`
* `bitbucket helper`

### SMB handler

* `proxy support`

### FTP handler

* `authenticated testing (should work, only tested anonymous so far)`
* `FTPS support`
* `proxy support`

### Zip handler

### Tar handler

### Framework

* `Support for pyc files`
* `Python3.12+ support`

### Etc

* `More documentation`
* `NFS handler`
* `Packaging`
* `Testing for other python distros`

## Gotchas

* This has currently only been tested on windows 10 and 11 with python 3.10, but in theory should work on any version 3.4-3.11
* If you update py3memimporter's shellcode to contain the version of _memimporter which is compatibly with 3.0-3.3 then, in theory, those versions should work as well.
* 3.12+ is not currently supported due to a functional change in the import protocol which has been depricated for some time, but was finally removed in 3.12.

## Special Thanks

* [natesubra](https://github.com/natesubra) - For challenging me to learn this stuff :D
* [operatorequals](https://github.com/operatorequals) - For httpimport, which is where I cut my teeth working on import hooks
* [desty2k](https://github.com/desty2k) - For Paker, which helped me figure out how to support packages with C extensions
* [py2exe](https://github.com/py2exe) - For _memimporter as well as the hooking logic for dynamic patching
