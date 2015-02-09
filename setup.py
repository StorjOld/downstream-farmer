#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
from setuptools.command.test import test as TestCommand
# import py2exe

LONG_DESCRIPTION = open('README.rst').read()

with open('downstream_farmer/version.py', 'r') as f:
    exec(f.read())

install_requirements = [
    'six',
    'requests',
    'RandomIO',
    'storj-heartbeat',
    'siggy',
    'colorama'
]

test_requirements = [
    'base58',
    'mock',
    'pytest',
    'pytest-pep8',
    'pytest-cache',
    'coveralls'
]


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # Import PyTest here because outside, the eggs are not loaded.
        import pytest
        import sys
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

dependencies = [
    'https://github.com/Storj/heartbeat/tarball/master#egg=storj-heartbeat-0.1.9',
    'https://github.com/Storj/RandomIO/tarball/master#egg=RandomIO-0.1.0',
    'https://github.com/Storj/siggy/tarball/master#egg=siggy-0.1.0'
]

setup(
    name='downstream-farmer',
    version=__version__,
    url='https://github.com/Storj/downstream-farmer',
    download_url='https://github.com/Storj/downstream-farmer/tarball/' +
        __version__,
    license=open('LICENSE').read(),
    author='Storj Labs',
    author_email='info@storj.io',
    description='Client software for a Storj farmer',
    long_description=LONG_DESCRIPTION,
    packages=['downstream_farmer'],
    cmdclass={'test': PyTest},
    install_requires=install_requirements,
    tests_require=test_requirements,
    dependency_links=dependencies,
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    },
    keywords=['storj', 'farmer', 'farming', 'driveshare']
)
