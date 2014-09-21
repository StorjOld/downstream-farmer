from setuptools import setup

from downstream_farmer import __version__

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
        'requests',
        'heartbeat==0.1.2'
    ],
    dependency_links=[
        'git+https://github.com/Storj/heartbeat.git@v0.1.2#egg=heartbeat-0.1.2'
    ],
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    }
)
