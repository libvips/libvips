#!/usr/bin/python

import gc
import sys

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0
from gi.repository import Vips

a = Vips.Image()
a.props.filename = sys.argv[1]
a.props.mode = 'r'
if a.build() != 0:
    print Vips.error_buffer()
    sys.exit(-1)

print 'a.get_width() =', a.get_width()
print 'a.props.width =', a.props.width

print 'starting shutdown ...'
del a
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

