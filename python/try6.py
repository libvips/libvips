#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

a = Vips.Image.new_from_file(sys.argv[1])

b = a.write_to_buffer(".jpg")

c = Vips.Image.new_from_buffer(b, "")
