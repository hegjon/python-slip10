import io

from setuptools import setup

import slip10

with io.open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with io.open("requirements.txt", encoding="utf-8") as f:
    requirements = [r for r in f.read().split("\n") if len(r)]

setup(
    name="slip10",
    version=slip10.__version__,
    description="Minimalistic implementation of the SLIP10 key derivation scheme",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trezor/python-slip10",
    author="Andrew R. Kozlik",
    author_email="andrew.kozlik@satoshilabs.com",
    license="MIT",
    packages=["slip10"],
    keywords=["bitcoin", "slip10", "hdwallet"],
    install_requires=requirements,
)
