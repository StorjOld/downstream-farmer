from setuptools import setup

from downstream_farmer import __version__

setup(
    name='downstream-farmer',
    version=__version__,
    packages=['downstream_farmer'],
    url='',
    license='',
    author='Storj Labs',
    author_email='info@storj.io',
    description='',
    install_requires=[
        'requests',
        'heartbeat==0.1.2'
    ],
    dependency_links=[
        'https://github.com/Storj/heartbeat/archive/v0.1.2.tar.gz#egg=heartbeat-0.1.2'
    ],
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    }
)
