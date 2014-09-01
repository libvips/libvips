#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

a = Vips.Image.new_from_file(sys.argv[1])

# test operator overloads
b = a + 12
b = a + [12, 0, 0]
b = a + b

b.write_to_file(sys.argv[2])
