#!/usr/bin/python

import logging
import gc

import vipsimage

logging.basicConfig(level = logging.DEBUG)

# test unref
for i in range (1,10):
    a = vipsimage.VipsImage('/home/john/pics/healthygirl.jpg')

# should work
a = vipsimage.VipsImage('/home/john/pics/healthygirl.jpg')
print 'width =', a.width()
print 'height =', a.height()
print 'bands =', a.bands()
print 'format =', vipsimage.VipsBandFormat.name(a.format())
print 'coding =', vipsimage.VipsCoding.name(a.coding())
print 'interpretation =', vipsimage.VipsInterpretation.name(a.interpretation())
print 'xres =', a.xres()
print 'yres =', a.yres()
print 'xoffset =', a.xoffset()
print 'yoffset =', a.yoffset()

# should raise an error
# a = vipsimage.VipsImage('banana')

print 'starting shutdown ...'
del a
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

