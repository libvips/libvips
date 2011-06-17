#!/usr/bin/python

"""This module wraps up libvips in a less awful interface.

Author: J.Cupitt
GNU LESSER GENERAL PUBLIC LICENSE
"""

import logging
import ctypes

import vipsobject

libvips = vipsobject.libvips

vips_image_new = libvips.vips_image_new
vips_image_new.restype = vipsobject.check_pointer_return

vips_image_new_from_file = libvips.vips_image_new_from_file
vips_image_new_from_file.restype = vipsobject.check_pointer_return
vips_image_new_from_file.argtypes = [ctypes.c_char_p]

vips_image_new_mode = libvips.vips_image_new_mode
vips_image_new_mode.restype = vipsobject.check_pointer_return
vips_image_new_mode.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

vips_image_write = libvips.vips_image_write
vips_image_write.restype = vipsobject.check_int_return
vips_image_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

class VipsImage(vipsobject.VipsObject):
    """Manipulate a libvips image."""

    def __init__(self, filename = None, mode = None):
        logging.debug('vipsimage: init')

        vipsobject.VipsObject.__init__(self)

        if filename == None and mode == None:
            self.vipsobject = vips_image_new()
        elif filename != None and mode == None:
            self.vipsobject = vips_image_new_from_file(filename)
        else:
            self.vipsobject = vips_image_new_mode(filename, mode)

    def write(self, filename):
        vips_image_write(self.vipsobject, filename)



