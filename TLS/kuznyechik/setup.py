from Cython.Build import cythonize
from setuptools import setup, Extension

extension = Extension('kuznyechik', sources=['kuznyechik.pyx', 'src/Kuznechik.c'], language='c')
setup(name='kuznyechik', ext_modules=cythonize(extension))
