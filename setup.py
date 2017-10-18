from setuptools import setup, find_packages

setup(
    name='agentk',
    version='0.1.0',
    author='Thiago Borges Abdnur',
    author_email='bolaum@gmail.com',
    scripts=['bin/agentk'],
    license='LICENSE',
    description='SSH agent for kkmip.',
    long_description='README.md',
    install_requires=[
        "config",
    ],
)
