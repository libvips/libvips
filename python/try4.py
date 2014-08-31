#!/usr/bin/python

import sys

import logging
logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

a = Vips.Image.new_from_file(sys.argv[1])

b = Vips.Image.new_from_file(sys.argv[2])

c = a.join(b, Vips.Direction.HORIZONTAL, expand = True)

c.write_to_file(sys.argv[3])
