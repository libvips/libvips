#!/usr/bin/python

"""This module wraps up libvips in a less awful interface.

Wrap VipsObject.

Author: J.Cupitt
GNU LESSER GENERAL PUBLIC LICENSE
"""

import logging
import sys
import ctypes

import gobject

import finalizable

# .15 is 7.25+ with the new vips8 API
libvips = ctypes.CDLL('libvips.so.15')
libvips.vips_init(sys.argv[0])

vips_object_print = libvips.vips_object_print
vips_object_print.argtypes = [ctypes.c_void_p]
vips_object_print.restype = None

# in C:
# typedef void *(*VipsArgumentMapFn)( VipsObject *, 
#   GParamSpec *, VipsArgumentClass *, VipsArgumentInstance *, 
#   void *a, void *b );
VipsArgumentMapFn = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, 
        ctypes.c_void_p, ctypes.c_void_p)
vips_argument_map = libvips.vips_argument_map
vips_argument_map.argtypes = [ctypes.c_void_p, VipsArgumentMapFn,
        ctypes.c_void_p, ctypes.c_void_p]
vips_argument_map.restype = ctypes.c_void_p

g_param_spec_get_name = libvips.g_param_spec_get_name
g_param_spec_get_name.argtypes = [ctypes.c_void_p]
g_param_spec_get_name.restype = ctypes.c_char_p

# given a class and value, search for a class member with that value
# handy for enum classes, use to turn numbers to strings
def class_value(classobject, value):
    for name in dir(classobject):
        if getattr(classobject, name) == value:
            return classobject.__name__ + '.' + name

    return 'unknown'

class VipsError(Exception):

    """An error from libvips.

    message -- a high-level description of the error
    detail -- a string with some detailed diagnostics
    """

    def __init__(self, message):
        self.message = message
        self.detail = vips_error_buffer()
        libvips.vips_error_clear()

        logging.debug('vipsobject: Error: %s %s', self.message, self.detail)

    def __str__(self):
        return '%s %s' % (self.message, self.detail)

# handy checkers, assign to errcheck
def check_int_return(result, func, args):
    if result != 0:
        raise VipsError('Error calling vips function %s.' % func.__name__)
    return result

def check_pointer_return(result, func, args):
    if result == None:
        raise VipsError('Error calling vips function %s.' % func.__name__)
    return result

vips_error_buffer = libvips.vips_error_buffer
vips_error_buffer.restype = ctypes.c_char_p

class VipsObject(finalizable.Finalizable):
    """Abstract base class for libvips."""

    # attributes we finalize
    ghost_attributes = ('vipsobject', )

    def __finalize__(self):
        logging.debug('vipsobject: __finalize__')

        if self.vipsobject != None:
            logging.debug('vipsobject: unref %s' % hex(self.vipsobject))
            libvips.g_object_unref(self.vipsobject)
            self.vipsobject = None

    def enable_finalize(self):
        self.bind_finalizer(*self.ghost_attributes)

    def __init__(self):
        logging.debug('vipsobject: init')

        self.vipsobject = None
