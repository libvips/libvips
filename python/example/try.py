#!/usr/bin/python

import sys

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

print 'long way around:'

a = Vips.Image()
a.props.filename = sys.argv[1]
a.props.mode = 'r'
if a.build() != 0:
    print Vips.error_buffer()
    sys.exit(-1)

print 'a.get_width() =', a.get_width()
print 'a.props.width =', a.props.width

print 'via foreign load system:'

loader = Vips.Foreign.find_load(sys.argv[1])
if loader == None:
    print Vips.error_buffer()
    sys.exit(-1)

op = Vips.Operation.new(loader)
for prop in op.props:
    print 'prop.name =', prop.name
    flags = op.get_argument_flags(prop.name)
    if flags & Vips.ArgumentFlags.OUTPUT:
        print '\toutput'
    if flags & Vips.ArgumentFlags.INPUT:
        print '\tinput'
    if flags & Vips.ArgumentFlags.REQUIRED:
        print '\trequired'
    print '\tisset', op.argument_isset(prop.name)

op.props.filename = sys.argv[1]

op2 = Vips.cache_operation_build(op)
if op2 == None:
    print Vips.error_buffer()
    sys.exit(-1)

b = op2.props.out

op2.unref_outputs()

print 'b.get_width() =', b.get_width()
print 'b.props.width =', b.props.width

print 'call operation:'

op = Vips.Operation.new("add")
for prop in op.props:
    print 'prop.name =', prop.name
    flags = op.get_argument_flags(prop.name)
    if flags & Vips.ArgumentFlags.OUTPUT:
        print '\toutput'
    if flags & Vips.ArgumentFlags.INPUT:
        print '\tinput'
    if flags & Vips.ArgumentFlags.REQUIRED:
        print '\trequired'
    print '\tisset', op.argument_isset(prop.name)

op.props.left = a
op.props.right = b
op2 = Vips.cache_operation_build(op)
if op2 == None:
    print Vips.error_buffer()
    sys.exit(-1)
out = op2.props.out
op2.unref_outputs()

print 'out.get_format() =', out.get_format()
print 'out.props.format =', out.props.format

print 'save via foreign save system:'

saver = Vips.Foreign.find_save("x.v")
if saver == None:
    print Vips.error_buffer()
    sys.exit(-1)

op = Vips.Operation.new(saver)
for prop in op.props:
    print 'prop.name =', prop.name
    flags = op.get_argument_flags(prop.name)
    if flags & Vips.ArgumentFlags.OUTPUT:
        print '\toutput'
    if flags & Vips.ArgumentFlags.INPUT:
        print '\tinput'
    if flags & Vips.ArgumentFlags.REQUIRED:
        print '\trequired'
    print '\tisset', op.argument_isset(prop.name)

setattr(op.props, "in", out)
op.props.filename = "x.v"

op2 = Vips.cache_operation_build(op)
if op2 == None:
    print Vips.error_buffer()
    sys.exit(-1)

op2.unref_outputs()

print 'generic call:'

def required_input(flags):
    enm = Vips.ArgumentFlags
    return flags & enm.INPUT and flags & enm.REQUIRED

def optional_input(flags):
    enm = Vips.ArgumentFlags
    return flags & enm.INPUT and not flags & enm.REQUIRED

def required_output(flags):
    enm = Vips.ArgumentFlags
    return flags & enm.OUTPUT and flags & enm.REQUIRED

def optional_output(flags):
    enm = Vips.ArgumentFlags
    return flags & enm.OUTPUT and not flags & enm.REQUIRED

def vips_call(name, *required, **optional):
    op = Vips.Operation.new(name)

    # set required input args
    i = 0
    for prop in op.props:
        flags = op.get_argument_flags(prop.name)
        if required_input(flags):
            if i >= len(required):
                print 'too few required args!'

            op.props.__setattr__(prop.name, required[i])
            i += 1

    if i < len(required):
        print 'too many required args!'

    # set optional input args
    for i in optional.keys():
        flags = op.get_argument_flags(i)
        if optional_input(flags):
            op.props.__setattr__(i, optional[i])

    # call
    op2 = Vips.cache_operation_build(op)
    if op2 == None:
        print Vips.error_buffer()

    # gather output args 
    out = []
    for prop in op2.props:
        flags = op2.get_argument_flags(prop.name)
        if required_output(flags):
            out.append(op2.props.__getattribute__(prop.name))
    for i in optional.keys():
        flags = op2.get_argument_flags(i)
        if optional_output(flags):
            out.append(op2.props.__getattribute__(i))

    if len(out) == 1:
        out = out[0]

    # unref everything now we have refs to all outputs we want
    op2.unref_outputs()

    return out

im = vips_call("add", a, b)

print 'save via foreign save system:'

saver = Vips.Foreign.find_save("x2.v")
if saver == None:
    print Vips.error_buffer()
    sys.exit(-1)

op = Vips.Operation.new(saver)
for prop in op.props:
    print 'prop.name =', prop.name
    flags = op.get_argument_flags(prop.name)
    if flags & Vips.ArgumentFlags.OUTPUT:
        print '\toutput'
    if flags & Vips.ArgumentFlags.INPUT:
        print '\tinput'
    if flags & Vips.ArgumentFlags.REQUIRED:
        print '\trequired'
    print '\tisset', op.argument_isset(prop.name)

setattr(op.props, "in", im)
op.props.filename = "x2.v"

op2 = Vips.cache_operation_build(op)
if op2 == None:
    print Vips.error_buffer()
    sys.exit(-1)

op2.unref_outputs()
