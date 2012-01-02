#!/usr/bin/python

"""This module wraps up libvips in a less awful interface.

Author: J.Cupitt
GNU LESSER GENERAL PUBLIC LICENSE
"""

import logging
import ctypes

import gobject

import vipsobject

libvips = vipsobject.libvips

vips_operation_new = libvips.vips_operation_new
vips_operation_new.argtypes = [ctypes.c_char_p]
vips_operation_new.restype = ctypes.c_void_p
vips_operation_new.errcheck = vipsobject.check_pointer_return

def show_args(operation, pspec, arg_class, arg_instance, a, b):
    name = vipsobject.g_param_spec_get_name(pspec)

def vips_call_instance(self, name, args):
    logging.debug('vipsimage: vips_call_instance name=%s, self=%s, args=%s' % 
                  (name, self, args))
    operation = vips_operation_new(name)
    vipsobject.vips_object_print(operation)
    vipsobject.vips_argument_map(operation, 
            vipsobject.VipsArgumentMapFn(show_args),None, None)

class VipsOperation(vipsobject.VipsObject):
    """Call a libvips operation."""

    def __init__(self, name):
        logging.debug('vipsoperation: init %s', name)

        vipsobject.VipsObject.__init__(self)

        self.vipsobject = vips_operation_new(name)

        self.enable_finalize()

    def call
