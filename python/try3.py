#!/usr/bin/python

import sys
from vips8 import vips

from gi.repository import Vips
Vips.cache_set_trace(True)

a = vips.Image(sys.argv[1])
print a.max()
print a.max()

