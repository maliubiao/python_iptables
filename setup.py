#! /usr/bin/env python
from distutils.core import setup, Extension

m = Extension('_sockopt',
        sources = ['sockopt.c'] 
        )


setup(name = 'iptables',
        version = '1.0',
        description = 'python native library for netfilter',
        ext_modules = [m])
