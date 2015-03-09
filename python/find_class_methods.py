#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips, GObject

# Search for all VipsOperation which don't have an input image object ... these
# should be class methods and need to have their names pasted into Vips.py

# This is slow :-( so we don't do this dynamically

vips_type_image = GObject.GType.from_name("VipsImage")
vips_type_operation = GObject.GType.from_name("VipsOperation")

def find_class_methods(cls):
    if not cls.is_abstract():
        op = Vips.Operation.new(cls.name)

        found = False
        for prop in op.props:
            flags = op.get_argument_flags(prop.name)
            if not flags & Vips.ArgumentFlags.INPUT:
                continue
            if not flags & Vips.ArgumentFlags.REQUIRED:
                continue
            if GObject.type_is_a(vips_type_image, prop.value_type):
                found = True
                break

        if not found:
            gtype = Vips.type_find("VipsOperation", cls.name)
            nickname = Vips.nickname_find(gtype)
            print '    "%s",' % nickname

    if len(cls.children) > 0:
        for child in cls.children:
            # not easy to get at the deprecated flag in an abtract type?
            if cls.name != 'VipsWrap7':
                find_class_methods(child)

print 'found class methods:'

find_class_methods(vips_type_operation)

