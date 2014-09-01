#!/usr/bin/python

import sys

import logging

from gi.repository import GLib
from gi.repository import GObject

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0
from gi.repository import Vips 

# start up vips!
Vips.init(sys.argv[0])

# need the gtypes for various vips types
vips_type_array_int = GObject.GType.from_name("VipsArrayInt")
vips_type_array_double = GObject.GType.from_name("VipsArrayDouble")
vips_type_array_image = GObject.GType.from_name("VipsArrayImage")
vips_type_image = GObject.GType.from_name("VipsImage")

class Error(Exception):

    """An error from vips.

    message -- a high-level description of the error
    detail -- a string with some detailed diagnostics
    """

    def __init__(self, message, detail = None):
        self.message = message
        if detail == None:
            detail = Vips.error_buffer()
            Vips.error_clear()
        self.detail = detail

        logging.debug('vips: Error %s %s', self.message, self.detail)

    def __str__(self):
        return '%s\n  %s' % (self.message, self.detail)

class Argument:
    def __init__(self, op, prop):
        self.op = op;
        self.prop = prop;
        self.name = prop.name;
        self.flags = op.get_argument_flags(self.name)
        self.priority = op.get_argument_priority(self.name)
        self.isset = op.argument_isset(self.name)

    def set_value(self, value):
        logging.debug('assigning %s to %s' % (value, self.name))
        logging.debug('%s needs a %s' % (self.name, self.prop.value_type))
        
        # array-ize some types, if necessary
        if not isinstance(value, list):
            if GObject.type_is_a(self.prop.value_type, vips_type_array_int):
                value = Vips.ArrayInt.new([value])
            if GObject.type_is_a(self.prop.value_type, vips_type_array_double):
                value = Vips.ArrayDouble.new([value])
            if GObject.type_is_a(self.prop.value_type, vips_type_array_image):
                value = Vips.ArrayImage.new([value])

        logging.debug('assigning %s' % self.prop.value_type)

        self.op.props.__setattr__(self.name, value)

def _call_base(name, required, optional, self = None, option_string = None):
    logging.debug('_call_base name=%s, required=%s optional=%s' % 
                  (name, required, optional))
    if self:
        logging.debug('_call_base self=%s' % self)
    if option_string:
        logging.debug('_call_base option_string = %s' % option_string)

    try:
        op = Vips.Operation.new(name)
    except TypeError, e:
        raise Error('No such operator.')

    # set str options first so the user can't override things we set
    # deliberately and break stuff
    if option_string:
        if op.set_from_string(option_string) != 0:
            raise Error('Bad arguments.')

    # find all the args for this op, sort into priority order
    args = [Argument(op, x) for x in op.props]
    args.sort(lambda a, b: a.priority - b.priority)

    enm = Vips.ArgumentFlags

    # find all required, unassigned input args
    required_input = [x for x in args if x.flags & enm.INPUT and 
                      x.flags & enm.REQUIRED and 
                      not x.isset]

    # do we have a non-None self pointer? this is used to set the first
    # compatible input arg
    if self != None:
        found = False
        for x in required_input:
            if GObject.type_is_a(self, x.prop.value_type):
                x.set_value(self)
                required_input.remove(x)
                found = True
                break

        if not found:
            raise Error('Bad arguments.', 'No %s argument to %s.' %
                        (str(self.__class__), name))

    if len(required_input) != len(required):
        raise Error('Wrong number of arguments.', 
                    '%s needs %d arguments, you supplied %d' % 
                    (name, len(required_input), len(required)))

    for i in range(len(required_input)):
        required_input[i].set_value(required[i])

    # find all optional, unassigned input args ... make a hash from name to
    # Argument
    optional_input = {x.name: x for x in args if x.flags & enm.INPUT and 
                      not x.flags & enm.REQUIRED and 
                      not x.isset}

    # set optional input args
    for key in optional.keys():
        if not key in optional_input:
            raise Error('Unknown argument.', 
                        'Operator %s has no argument %s' % (name, key))
        optional_input[key].set_value(optional[key])

    # call
    op2 = Vips.cache_operation_build(op)
    if op2 == None:
        raise Error('Error calling operator %s.' % name)

    # find all required output args ... just need the names
    # we can't check assigned here (since we captured the value before the call)
    # but the getattr will test that for us anyway
    required_output = [x.name for x in args if x.flags & enm.OUTPUT and 
                       x.flags & enm.REQUIRED]

    # gather output args 
    out = []
    for x in required_output:
        out.append(op2.props.__getattribute__(x))

    # find all optional output args ... just need the names
    optional_output = [x.name for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    for x in optional.keys():
        if x in optional_output:
            out.append(op2.props.__getattribute__(x))

    if len(out) == 1:
        out = out[0]

    # unref everything now we have refs to all outputs we want
    op2.unref_outputs()

    logging.debug('success, out = %s' % out)

    return out

# general user entrypoint 
def call(name, *args, **kwargs):
    return _call_base(name, args, kwargs)

# here from getattr ... try to run the attr as a method
def _call_instance(self, name, args, kwargs):
    return _call_base(name, args, kwargs, self)

# this is a class method
def vips_image_new_from_file(cls, vips_filename, **kwargs):
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    loader = Vips.Foreign.find_load(filename)
    if loader == None:
        raise Error('No known loader for "%s".' % filename)
    logging.debug('Image.new_from_file: loader = %s' % loader)

    return _call_base(loader, [filename], kwargs, None, option_string)

def vips_image_getattr(self, name):
    logging.debug('Image.__getattr__ %s' % name)

    # look up in props first, eg. x.props.width
    if name in dir(self.props):
        return getattr(self.props, name)

    return lambda *args, **kwargs: _call_instance(self, name, args, kwargs)

def vips_image_write_to_file(self, vips_filename, **kwargs):
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    saver = Vips.Foreign.find_save(filename)
    if saver == None:
        raise Error('No known saver for "%s".' % filename)
    logging.debug('Image.write_to_file: saver = %s' % saver)

    _call_base(saver, [filename], kwargs, self, option_string)

def vips_add(self, other):
    if isinstance(other, Vips.Image):
        return self.add(other)
    else:
        return self.linear(1, other)

def vips_sub(self, other):
    if isinstance(other, Vips.Image):
        return self.subtract(other)
    else:
        return self.linear(1, -1 * other)

def vips_mul(self, other):
    if isinstance(other, Vips.Image):
        return self.multiply(other)
    else:
        return self.linear(other, 0)

# paste our methods into Vips.Image

# class methods
setattr(Vips.Image, 'new_from_file', classmethod(vips_image_new_from_file))

# instance methods
Vips.Image.write_to_file = vips_image_write_to_file
Vips.Image.__getattr__ = vips_image_getattr
Vips.Image.__add__ = vips_add
Vips.Image.__sub__ = vips_sub
Vips.Image.__mul__ = vips_mul

# Add other classes to Vips
Vips.Error = Error
Vips.Argument = Argument
Vips.call = call

