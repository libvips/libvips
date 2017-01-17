#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 

a = Vips.Image.new_from_file(sys.argv[1])

b = a.write_to_memory()

c = Vips.Image.new_from_memory(b, a.width, a.height, a.bands, a.bandfmt)

c.write_to_file("x.v")
