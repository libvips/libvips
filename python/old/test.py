#!/usr/bin/python

import logging
import gc

import gobject

import vipsobject
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
print 'format = %d - %s' % (a.format(), 
        vipsimage.VipsBandFormat.name(a.format()))
print 'coding = %d - %s' % (a.coding(), 
        vipsimage.VipsCoding.name(a.coding()))
print 'interpretation = %d - %s' % (a.interpretation(),
        vipsimage.VipsInterpretation.name(a.interpretation()))
print 'xres =', a.xres()
print 'yres =', a.yres()
print 'xoffset =', a.xoffset()
print 'yoffset =', a.yoffset()

# should raise an error
try:
    a = vipsimage.VipsImage('banana')
except vipsobject.VipsError, e:
    print 'caught VipsError'
    print '\tmessage =', e.message
    print '\tdetail =', e.detail

# try calling a vips8 method
a = vipsimage.VipsImage('/home/john/pics/healthygirl.jpg')
b = vipsimage.VipsImage('/home/john/pics/babe.jpg')
c = a.add(b)

print 'c = ', c

c.write('/home/john/pics/x.v')

print 'starting shutdown ...'
del a
del b
del c
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
	gc.collect ()
print 'shutdown!'

