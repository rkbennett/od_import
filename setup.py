from setuptools import setup, find_packages

setup(
    name="od_import",
    version="0.0.1",
    description="A Python package for remote, in-memory Python package/module importing via HTTP/S, FTP, or SMB.",
    author="rkbennett",
    author_email="r.k.bennett@hotmail.com",
    packages=find_packages(),
    python_requires=">=3.6",
)
