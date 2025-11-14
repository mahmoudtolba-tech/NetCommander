"""
Setup script for building C++ fast_ping module
"""
from setuptools import setup, Extension
import sys

# Module definition
fast_ping_module = Extension(
    'fast_ping',
    sources=['fast_ping.cpp'],
    extra_compile_args=['-O3', '-Wall'],
    language='c++'
)

setup(
    name='fast_ping',
    version='1.0',
    description='High-performance ICMP ping module',
    ext_modules=[fast_ping_module],
)
