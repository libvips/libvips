#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

Vips.cache_set_trace(True)

a = Vips.Image.new_from_file(sys.argv[1])
print a.max()
print a.max()

