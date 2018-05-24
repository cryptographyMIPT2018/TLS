from Cython.Build import cythonize
from setuptools import setup, Extension

extension = Extension('kuznyechik', sources=['kuznyechik.pyx'], language='c++',
                      extra_compile_args=['--std=c++11'])
setup(name='kuznyechik', ext_modules=cythonize(extension))
