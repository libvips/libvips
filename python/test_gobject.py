#!/usr/bin/python

import logging
import gc
import sys
import ctypes

import gobject

logging.basicConfig(level = logging.DEBUG)

# .15 is 7.25+ with the new vips8 API
libvips = ctypes.CDLL('libvips.so.15')
libvips.vips_init(sys.argv[0])

# should be able to find vipsimage, hopefully
print gobject.type_from_name('VipsImage')

_VipsImage = gobject.type_from_name('VipsImage')

class VipsImage(_VipsImage):
    def __new__(cls):
        gobject.type_register(cls)
        return gobject.GObject.__new__(cls)

    def __init__(self, filename = None, mode = None):
        logging.debug('vipsimage: init')

        if filename != None:
            self.props.filename = filename

        if mode != None:
            self.props.mode = mode

a = VipsImage('/home/john/pics/healthygirl.jpg')
# a = gobject.new(VipsImage, '/home/john/pics/healthygirl.jpg')
