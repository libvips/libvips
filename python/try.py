#!/usr/bin/python

import gc
import sys

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0
from gi.repository import Vips

print 'long way around:'

a = Vips.Image()
a.props.filename = sys.argv[1]
a.props.mode = 'r'
if a.build() != 0:
    print Vips.error_buffer()
    sys.exit(-1)

print 'a.get_width() =', a.get_width()
print 'a.props.width =', a.props.width

print 'direct call:'

a = Vips.Image.new_from_file(sys.argv[1])

print 'a.get_width() =', a.get_width()
print 'a.props.width =', a.props.width

print 'call operation:'

op = Vips.Operation.new("add")
for prop in op.props:
    print 'prop =', prop
op.props.left = a
op.props.right = a
if op.build() != 0:
    print Vips.error_buffer()
    sys.exit(-1)
out = op.props.out

print 'out.get_format() =', out.get_format()
print 'out.props.format =', out.props.format

out.write_to_file("x.v")

print 'starting shutdown ...'
del a
del op
del out

# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

