from Cython.Build import cythonize
from setuptools import setup, Extension
import shutil
import os

extension = Extension('kuznyechik', sources=['kuznyechik.pyx'], language='c++',
                      extra_compile_args=['--std=c++11'])
setup(name='kuznyechik', ext_modules=cythonize(extension))

shutil.rmtree('build')
os.remove('kuznyechik.cpython-36m-darwin.so')
os.remove('kuznyechik.cpp')
