#!/usr/bin/python

import logging
logging.basicConfig(level = logging.DEBUG)

from vips8 import vips

from gi.repository import Vips
Vips.cache_set_trace(True)

try:
    a = vips.Image("/home/john/pics/babe.poop")
except vips.Error, e:
    print e

a = vips.Image("/home/john/pics/babe.jpg")
b = vips.Image("/home/john/pics/xmaspank2b.jpg")

print 'a =', a
print 'b =', b

out = vips.call("add", a, b)

print 'out =', out

out = a.add(b)

print 'out =', out

out = a.linear(1, 2)
