# od_import (off-disk import)

_Remote_, _in-memory_ Python _package/module_ importing **via HTTP/S, FTP, or SMB**

## **Compatible with Python 3.6+**

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

### Load package/module via HTTPS location without certificate verification

```python
config = {"verify": False}
with od_import.remote_source('http://my-packages.local/site-packages', config=config):
  import package
```

### Load package/module via HTTPS location with custom certificate trust

```python
crt = open("my-ca-crt.crt").read()
config = {"ca_data": crt}
with od_import.remote_source('http://my-packages.local/site-packages', config=config):
  import package
```

### Load package/module via S3 bucket

```python
config = {"type": "s3", "access_key": "MYACCESSKEY", "bucket": "mybucket", "secret_key": "MYSECRETKEY", "region": "us-east-1"}
with od_import.remote_source("https://amazonaws.com", config=config):
  import mypackage
```

### Load package/module via GITHUB repo (uses github.com and raw.githubusercontent.com) - github example

```python
config={"type": "git", "git": "github", "user": "rkbennett", "repo": "py3memimporter"}
with od_import.remote_source('https://github.com', config=config):
  import py3memimporter
```

### Load package/module via GITLAB repo - gitlab example

```python
config={"type": "git", "git": "gitlab", "group": "mygroup/mysubgroup", "project": "myproject", "api_key": "glpat_1234567890"}
with od_import.remote_source('https://my-gitlab.local', config=config):
  import project_package
```

### Load package/module via repo ZIP - github example

```python
config={"type": "git_zip", "git": "github", "user": "naksyn", "repo": "PythonMemoryModule"}
with od_import.remote_source('https://github.com', config=config):
  import pythonmemorymodule
```

### Load package/module via repo ZIP - gitlab example

```python
config={"type": "git_zip", "git": "gitlab", "group": "mygroup/mysubgroup", "project": "myproject", "api_key": "glpat_1234567890"}
with od_import.remote_source('https://gitlab.local', config=config):
  import myrepo_package
```

### Load package/module via repo API (would recommend you use the api_key config or you will be severely rate limited) - github example

```python
config={"api_key":"github_pat_somelongapikeystring", "type": "git_api", "git": "github", "user": "myuser", "repo": "myrepo"}
with od_import.remote_source('https://api.github.com', config=config):
  import py3memimporter
```

### Load package/module via repo API (would recommend you use the api_key config or you will be severely rate limited) - gitlab example

```python
config={"api_key":"glpat_1234567890", "type": "git_api", "git": "gitlab", "group": "mygroup/mysubgroup", "project": "myproject"}
with od_import.remote_source('https://my-gitlab.local', config=config):
  import mypackage
```

### Load package/module via pypi api

```python
config={"type": "pypi", "verify": False, "package": [{"name": "psutil", "release": "5.9.5"}]}
with od_import.remote_source('https://pypi.org/pypi', config=config):
  import psutil
```

### Load package/module via dropbox api (uses api.dropboxapi.com)

```python
config={"type": "dropbox", "verify": False, "access_token": "sl.mylongdropboxaccesstoken"}
with od_import.remote_source('https://dropbox.com/pybof', config=config):
  import bof
```

### Load package/module via pip (currently only works with python 3.12)

```python
config={"package": ["psutil"]}
with od_import.remote_source('pip', config=config):
  import psutil
```

### Load module via pastebin 

```python
config = {'type':'pastebin', 'visibility': 'passworded', 'paste_key': 'PaSt3Key', "module": "foo", "developer_key": "mydeveloperkey", "user_key": "myuserkey", "paste_password": "foobarbaz"}
with od_import.remote_source('https://pastebin.com', config=config):
  import foo
```

### Load package/module via s3 wrapper

```python
config = {"access_key": "MYACCESSKEY", "bucket": "mybucket", "secret_key": "MYSECRETKEY", "region": "us-east-1"}
with od_import.s3(**config):
  import my_package
```

### Load package/module via github wrapper

```python
with od_import.github("rkbennett", "py3memimporter", branch="main", git_type="git_zip", api_key="github_pat_somelongapikeystring"):
  import py3memimporter
```

### Load package/module via gitlab wrapper

```python
with od_import.gitlab("https://my-gitlab.local", "mygroup", "myproject", branch="main", git_type="git_api", api_key="glpat_1234567890", verify=False):
  import py3memimporter
```

### Load package/module via gitea wrapper

```python
with od_import.gitea("http://my-gitea.local", "rkbennett", "py3memimporter", branch="main", git_type="git", INSECURE=True):
  import py3memimporter
```

### Load package/module via pypi wrapper

```python
with od_import.pypi(package=[{"name": "psutil", "release": "5.9.5"}], verify=False):
  import psutil
```

### Load package/module via dropbox wrapper

```python
with od_import.dropbox("sl.mylongdropboxaccesstoken", path="/pybof", verify=False, timeout=30):
  import bof
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

* `username`
* `password`
* `timeout` (allows for setting the timeout of a connection)
* `http_version` (allows for downgrading http version to `HTTP/1.0` on requests)
* `headers` (dictionary of headers for requests, user-agent defaults to Python-urllib/3.x)
* `proxy` (Currently supports unauthenticated only)
* `verify` (enable/disable certificate verification for https certificates, defaults to `True`)
* `ca_file` (path to ca file for certificate trust)
* `ca_data` (string containing one more concatinated ca certificates)
* `type` (one of dir, s3, git, git_zip, or git_api; currently defaults to dir)
* `api_key` (only used for git, git_zip, and git_api types)
* `git` (only accepts `gitea`, `gitlab`, and `github` currently; only used for git_zip and git_api types)
* `package` (only used for pypi, can be a str of the package name, a dict of the package name and release or a list of package dicts)
* `user` (only used for github and gitea, owner of the target repo)
* `repo` (only used for github and gitea, the target repo)
* `group` (only used for gitlab, the full group path for the target project -- this includes subgroups)
* `project` (only used for gitlab, the target project)
* `branch` (only used for gitlab, github, and gitea, the desired branch of the target repo/project)
* `visibility` (only used for pastebin, must be one of `public`, `private`, `unlisted`, `burn`, or `passworded`)
* `module` (only used for pastebin, the fully-qualified name of the module you wish to import the paste as)
* `paste_key` (only used for pastebin, the id of the paste)
* `developer_key` (only used for pastebin when `visibility` set to `private`, `burn` or `passworded`)
* `user_key` (only used for pastebin when `visibility` set to `private`, `burn` or `passworded`)
* `paste_password` (only used for pastebin when `visibility` set to `passworded`)
* `access_token` (only used for dropbox)
* `http_provider` (only accepts `winhttp` currently; instructs web requests to use winhttp api calls instead of urllib -- only works on Windows)
* `access_key` (only used for s3 type)
* `secret_key` (only used for s3 type)
* `bucket` (only used for s3 types)
* `region` (only used for s3 types)


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

#### PIP

* `package` (can be list of package name strings or package name string)

## INSECURE

This is a boolean arg that is supplied to the hook constructor, which enables the use of insecure protocols (http, smb, ftp)

## Zip passwords

If you are importing from a zip which requires a password, you must provide the zip_password keyword arg to the hook constructor

## TODO

### HTTP handler

* `bitbucket helper`
* `add multiple gitlab token types to git helpers`

### SMB handler

* `proxy support`

### FTP handler

* `authenticated testing (should work, only tested anonymous so far)`
* `proxy support`

### Etc

* `Add obfuscator framework`
* `NFS handler`
* `Packaging`
* `Testing for other python distros`

## Gotchas

* This has currently only been tested on windows 10 and 11 with python 3.10-3.12, but in theory should work on any version 3.6+

## How to install

1. Download and install the Git client and Python on your device.
2. Open your terminal. (Make sure you have the necessary permissions to install packages on your system).
3. Execute the following command: `pip install git+https://github.com/rkbennett/od_import.git`

## Contributors

* [boludoz](https://github.com/boludoz) - gitignore and setup.py

## Special Thanks

* [natesubra](https://github.com/natesubra) - For challenging me to learn this stuff :D
* [operatorequals](https://github.com/operatorequals) - For httpimport, which is where I cut my teeth working on import hooks
* [desty2k](https://github.com/desty2k) - For Paker, which helped me figure out how to support packages with C extensions
* [py2exe](https://github.com/py2exe) - For the hooking logic for dynamic patching
* [SeaHOH](https://github.com/SeaHOH) - For _memimporter
