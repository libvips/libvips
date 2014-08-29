#!/usr/bin/python

import logging
logging.basicConfig(level = logging.DEBUG)

from vips8 import vips

from gi.repository import Vips
Vips.cache_set_trace(True)

try:
    a = Vips.Image.new_from_file("/home/john/pics/babe.poop")
except Vips.Error, e:
    print e

a = Vips.Image.new_from_file("/home/john/pics/babe.jpg")
b = Vips.Image.new_from_file("/home/john/pics/k2.jpg")

print 'a =', a
print 'b =', b

out = Vips.call("add", a, b)

print 'out =', out

out = a.add(b)

print 'out =', out

# we need to get GBoxed working for this
#out = a.linear(1, 2)
