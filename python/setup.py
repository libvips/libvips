#!/usr/bin/python

from distutils.core import setup

setup(name = 'vips8',
    version = '7.28.0dev',
    description = 'vips-8.x image processing library',
    long_description = open('README.txt').read(),
    license = 'LGPL'
    author = 'John Cupitt',
    author_email = 'jcupitt@gmail.com',
    url = 'http://www.vips.ecs.soton.ac.uk',
    requires = ['gi'],
    packages = ['vips8'])
