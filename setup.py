from setuptools import setup

setup(
    name='downstream-farmer',
    version='',
    packages=['downstream-farmer'],
    url='',
    license='',
    author='Storj Labs',
    author_email='info@storj.io',
    description='',
    install_requires=[
        'heartbeat==0.1.2'
    ],
    dependency_links = [
        'https://github.com/Storj/heartbeat/archive/v0.1.2.tar.gz#egg=heartbeat-0.1.2'
    ]
)
