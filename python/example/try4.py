#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 

a = Vips.Image.new_from_file(sys.argv[1])

b = Vips.Image.new_from_file(sys.argv[2])

c = a.join(b, Vips.Direction.HORIZONTAL, 
           expand = True, 
           shim = 100, 
           align = Vips.Align.CENTRE, 
           background = [128, 255, 128])

c.write_to_file(sys.argv[3])
