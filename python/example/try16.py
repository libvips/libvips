#!/usr/bin/python3

import sys

import logging
logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips

#Vips.cache_set_trace(True)

a = Vips.Image.new_from_file(sys.argv[1])

x = a.erode([[128, 255, 128], 
             [255, 255, 255],
             [128, 255, 128]])

x.write_to_file(sys.argv[2])


