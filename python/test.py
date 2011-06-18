#!/usr/bin/python

import logging
import gc

import gobject

import vipsimage

logging.basicConfig(level = logging.DEBUG)

# should be able to find vipsimage, hopefully
print gobject.type_from_name('VipsImage')

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
a = vipsimage.VipsImage('banana')

# try calling a vips8 method
a = vipsimage.VipsImage('/home/john/pics/healthygirl.jpg')
b = vipsimage.VipsImage('/home/john/pics/babe.jpg')
c = a.add(b)

print 'starting shutdown ...'
del a
del b
del c
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

