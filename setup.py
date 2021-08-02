#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Setup for pkiutils.
"""

__author__ = 'Jan Dittberner'

from setuptools import setup, find_packages


with open('README.rst', 'r') as readme:
    DESCRIPTION = readme.read()

DESCRIPTION += "\n"

with open('LICENSE', 'r') as license:
    DESCRIPTION += license.read()


setup(
    name='pkiutils',
    description='a set of public key infrastructure utilities',
    long_description=DESCRIPTION,
    install_requires=["pycryptodome", 'pyasn1', 'pyasn1_modules', 'netaddr'],
    version=0.1,
    author=__author__,
    author_email='jan@dittberner.info',
    url='https://github.com/jandd/python-pkiutils',
    packages=find_packages(),
    license='MIT',
)
