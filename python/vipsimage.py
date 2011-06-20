#!/usr/bin/python

"""This module wraps up libvips in a less awful interface.

Author: J.Cupitt
GNU LESSER GENERAL PUBLIC LICENSE
"""

import logging
import ctypes

import vipsobject

# image enums
class VipsDemandStyle:
    SMALLTILE = 0
    FATSTRIP = 1
    THINSTRIP = 2
    ANY = 3

    # turn 3 into 'ANY', handy for printing
    # is there a clever way to define this in a base Enum class? I can't think
    # of it
    @staticmethod
    def name(value):
        return vipsobject.class_value(VipsDemandStyle, value)

class VipsInterpretation:
    MULTIBAND = 0
    B_W = 1
    HISTOGRAM = 10
    FOURIER = 24
    XYZ = 12
    LAB = 13
    CMYK = 15
    LABQ = 16
    RGB = 17
    UCS = 18
    LCH = 19
    LABS = 21
    sRGB = 22
    YXY = 23
    RGB16 = 25
    GREY16 = 26

    @staticmethod
    def name(value):
        print currentclass
        return vipsobject.class_value(VipsInterpretation, value)

class VipsBandFormat:
    NOTSET = -1
    UCHAR = 0
    CHAR = 1
    USHORT = 2
    SHORT = 3
    UINT = 4
    INT = 5
    FLOAT = 6
    COMPLEX = 7
    DOUBLE = 8,
    DPCOMPLEX = 9
    LAST = 10

    @staticmethod
    def name(value):
        return vipsobject.class_value(VipsBandFormat, value)

class VipsCoding:
    NONE = 0
    LABQ = 2
    RAD = 6

    @staticmethod
    def name(value):
        return vipsobject.class_value(VipsCoding, value)

libvips = vipsobject.libvips

vips_image_new = libvips.vips_image_new
vips_image_new.restype = ctypes.c_void_p
vips_image_new.errcheck = vipsobject.check_pointer_return

vips_image_new_from_file = libvips.vips_image_new_from_file
vips_image_new_from_file.argtypes = [ctypes.c_char_p]
vips_image_new_from_file.restype = ctypes.c_void_p
vips_image_new_from_file.errcheck = vipsobject.check_pointer_return

vips_image_new_mode = libvips.vips_image_new_mode
vips_image_new_mode.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
vips_image_new_mode.restype = ctypes.c_void_p
vips_image_new_mode.errcheck = vipsobject.check_pointer_return

vips_image_write = libvips.vips_image_write
vips_image_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
vips_image_write.restype = ctypes.c_void_p
vips_image_write.errcheck = vipsobject.check_int_return

vips_image_get_xres = libvips.vips_image_get_xres
vips_image_get_xres.restype = ctypes.c_double;

vips_image_get_yres = libvips.vips_image_get_yres
vips_image_get_yres.restype = ctypes.c_double;

vips_operation_new = libvips.vips_operation_new
vips_operation_new.argtypes = [ctypes.c_char_p]
vips_operation_new.restype = ctypes.c_void_p
vips_operation_new.errcheck = vipsobject.check_pointer_return

def vips_call_instance(self, name, args):
    logging.debug('vipsimage: vips_call_instance name=%s, self=%s, args=%s' % 
                  (name, self, args))
    operation = vips_operation_new(name)

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

        logging.debug('vipsimage: made %s' % hex(self.vipsobject))

        self.enable_finalize()

    def __getattr__(self, name):
        logging.debug('vipsimage: __getattr__ %s' % name)
        return lambda *args: vips_call_instance(self, name, args)

    def width(self):
        return libvips.vips_image_get_width(self.vipsobject)

    def height(self):
        return libvips.vips_image_get_height(self.vipsobject)

    def bands(self):
        return libvips.vips_image_get_bands(self.vipsobject)

    def format(self):
        return libvips.vips_image_get_format(self.vipsobject)

    def coding(self):
        return libvips.vips_image_get_coding(self.vipsobject)

    def interpretation(self):
        return libvips.vips_image_get_interpretation(self.vipsobject)

    def xres(self):
        return vips_image_get_xres(self.vipsobject)

    def yres(self):
        return vips_image_get_yres(self.vipsobject)

    def xoffset(self):
        return libvips.vips_image_get_xoffset(self.vipsobject)

    def yoffset(self):
        return libvips.vips_image_get_yoffset(self.vipsobject)

    def write(self, filename):
        vips_image_write(self.vipsobject, filename)



