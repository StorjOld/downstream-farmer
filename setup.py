#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
# import py2exe

with open('downstream_farmer/version.py', 'r') as f:
    exec(f.read())

setup(
    name='downstream-farmer',
    version=__version__,
    packages=['downstream_farmer'],
    url='https://github.com/Storj/downstream-farmer',
    license='MIT',
    author='Storj Labs',
    author_email='info@storj.io',
    description='Client software for a Storj farmer',
    install_requires=[
        'six',
        'requests',
        'base58',
        'RandomIO',
        'storj-heartbeat',
        'siggy'
    ],
    dependency_links=[
        'https://github.com/Storj/heartbeat/tarball/master#egg=storj-heartbeat-0.1.5.1',
        'https://github.com/Storj/RandomIO/tarball/master#egg=RandomIO-0.1.0',
        'https://github.com/Storj/siggy/tarball/master#egg=siggy-0.1.0'
    ],
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    }
)
