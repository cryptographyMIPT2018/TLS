from setuptools import setup, Extension
import os
import shutil


with open('requirements.txt', 'r') as handler:
    requirements = [line.strip() for line in handler.readlines()]


setup(name='TLS', packages=['TLS'], install_requires=requirements)

for tmp_dir_path in ['build', 'dist', 'TLS.egg-info']:
    shutil.rmtree(tmp_dir_path)
