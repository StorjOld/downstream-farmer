#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
# import py2exe

LONG_DESCRIPTION = open('README.md').read()

with open('downstream_farmer/version.py', 'r') as f:
    exec(f.read())

install_requirements = [
    'six',
    'requests',
    'RandomIO',
    'storj-heartbeat',
    'siggy'
]

test_requirements = [
    'base58'
]

dependencies = [
    'https://github.com/Storj/heartbeat/tarball/master#egg=storj-heartbeat-0.1.5.1',
    'https://github.com/Storj/RandomIO/tarball/master#egg=RandomIO-0.1.0',
    'https://github.com/Storj/siggy/tarball/master#egg=siggy-0.1.0'
]

setup(
    name='downstream-farmer',
    version=__version__,
    packages=['downstream_farmer'],
    url='https://github.com/Storj/downstream-farmer',
    download_url='https://github.com/Storj/downstream-farmer/tarball/' +
        __version__,
    license=open('LICENSE').read(),
    author='Storj Labs',
    author_email='info@storj.io',
    description='Client software for a Storj farmer',
    keywords=['storj', 'farmer', 'farming', 'driveshare'],
    long_description=LONG_DESCRIPTION,
    install_requires=install_requirements,
    tests_require=test_requirements,
    dependency_links=dependencies,
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    }
)
