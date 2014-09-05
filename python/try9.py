#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

a = Vips.Image.black(100, 100)

b = Vips.Image.new_memory()

a.write(b)

b.write_to_file("x.v")
