#!/usr/bin/python

import sys

# just need this for leaktesting
import gc

from vipsCC import *

if len (sys.argv) != 3:
	print 'usage:', sys.argv[0], 'inputimage outputimage'
	print '\tcalculate photographic negative of inputimage'
	sys.exit (1)

try:
	a = VImage.VImage (sys.argv[1])
	b = a.invert ()
	c = b.lin ([1,2,3],[4,5,6])
	m = VMask.VIMask (3, 3, 1, 0, 
		   	  [-1, -1, -1, 
			   -1,  8, -1, 
			   -1, -1, -1])
	d = a.conv (m)
	d.write (sys.argv[2])
except VError.VError, e:
	e.perror (sys.argv[0])

# we can get properties of VImage too
print 'inputimage is', a.Xsize (), 'pixels across'

print 'starting shutdown ...'
del b
del a
del c
del d
del m
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

print 'leaked IMAGEs:'
VImage.im__print_all ()
print 'done ... hopefully you saw no leaks'
