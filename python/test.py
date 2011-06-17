#!/usr/bin/python

import logging

import vipsimage

logging.basicConfig(level = logging.DEBUG)

# should work
a = vipsimage.VipsImage('/home/john/pics/healthygirl.jpg')
a.write('x.png')

# should raise an error
a = vipsimage.VipsImage('banana')
