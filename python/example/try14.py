#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

a = Vips.Image.black(100, 100)
b = a.bandjoin(2)

b.write_to_file("x.v")
