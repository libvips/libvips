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

ones = Vips.array_double_new([1])
twos = Vips.array_double_new([2])

out = out.linear(ones, twos)

out.write_to_file("x.v")
