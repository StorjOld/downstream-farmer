from setuptools import setup

with open('downstream_farmer/version.py','r') as f:
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
        'requests',
        'base58',
        'RandomIO',
        'storj-heartbeat'
    ],
    entry_points={
        'console_scripts': [
            'downstream = downstream_farmer.shell:main'
        ]
    }
)
