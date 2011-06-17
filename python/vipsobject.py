#!/usr/bin/python

"""This module wraps up libvips in a less awful interface.

Wrap VipsObject.

Author: J.Cupitt
GNU LESSER GENERAL PUBLIC LICENSE
"""

import logging
import sys
import ctypes

import finalize

# .15 is 7.25+ with the new vips8 API
libvips = ctypes.CDLL('libvips.so.15')
libvips.vips_init(sys.argv[0])

class Error(Exception):

    """An error from libvips.

    message -- a high-level description of the error
    detail -- a string with some detailed diagnostics
    """

    def __init__(self, message):
        self.message = message
        self.detail = vips_error_buffer()
        libvips.vips_error_clear()

        logging.debug('vipsobject: Error %s %s', self.message, self.detail)

    def __str__(self):
        return '%s - %s' %(self.message, self.detail)

def check_int_return(value):
    if value != 0:
        raise Error('Error calling vips function.')
    return value

def check_pointer_return(value):
    if value == None:
        raise Error('Error calling vips function.')
    return value

vips_error_buffer = libvips.vips_error_buffer
vips_error_buffer.restype = ctypes.c_char_p

class VipsObject:
    """Abstract base class for libvips."""

    def unref_vips(self):
        if self.vipsobject != None:
            libvips.g_object_unref(self.vipsobject)
            self.vipsobject = None

    def __init__(self):
        logging.debug('vipsobject: init')

        self.vipsobject = None
        finalize.track(self, self, self.unref_vips)


