#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

a = Vips.Image.new_from_file(sys.argv[1])

ipct = a.get("ipct-data")

print "ipct = ", ipct.get()

a.remove("ipct-data")

a.write_to_file("x.jpg")
