#!/usr/bin/python

import sys
from vips8 import vips
from gi.repository import Vips

a = vips.Image(sys.argv[1])
b = vips.Image(sys.argv[2])

c = a.join(b, Vips.Direction.HORIZONTAL, expand = True)

c.write_to_file(sys.argv[3])
