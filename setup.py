import os
import sys

from distutils.core import setup


setup(
    name="ssl-checker",
    version="1.0.0",
    description="SSL Checker",
    long_description="This is an SSL Checker",
    long_description_content_type="text/markdown",
    url="",
    author="Abdelrahman Seleem",
    author_email="seleem@ieee.org",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    packages=["ssl_checker"],
    include_package_data=True,
    install_requires=[
        "prettytable==3.8.0", "python-dateutil==2.8.2"
    ],
    entry_points={"console_scripts": ["ssl_checker=app.__main__:main"]},
)
