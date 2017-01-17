#!/usr/bin/python3

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

#Vips.cache_set_trace(True)

a = Vips.Image.new_from_file(sys.argv[1])

a = a[1:]

a.write_to_file(sys.argv[2])


