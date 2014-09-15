#!/usr/bin/python

import sys
import re

import logging

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0

from gi.repository import GLib, GObject, Vips

# start up vips!
Vips.init(sys.argv[0])

# need the gtypes for various vips types
vips_type_array_int = GObject.GType.from_name("VipsArrayInt")
vips_type_array_double = GObject.GType.from_name("VipsArrayDouble")
vips_type_array_image = GObject.GType.from_name("VipsArrayImage")
vips_type_blob = GObject.GType.from_name("VipsBlob")
vips_type_image = GObject.GType.from_name("VipsImage")
vips_type_operation = GObject.GType.from_name("VipsOperation")

unpack_types = [Vips.Blob, Vips.ArrayDouble, Vips.ArrayImage, Vips.ArrayInt]
def isunpack(obj):
    for t in unpack_types:
        if isinstance(obj, t):
            return True
    return False

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
        self.name = re.sub("-", "_", prop.name);
        self.flags = op.get_argument_flags(self.name)
        self.priority = op.get_argument_priority(self.name)
        self.isset = op.argument_isset(self.name)

    def arrayize(self, vips_type_array, vips_cast, value):
        if GObject.type_is_a(self.prop.value_type, vips_type_array):
            if not isinstance(value, list):
                value = [value]
            value = vips_cast(value)

        return value

    def set_value(self, value):
        logging.debug('assigning %s to %s' % (value, self.name))
        logging.debug('%s needs a %s' % (self.name, self.prop.value_type))

        # array-ize some types, if necessary
        value = self.arrayize(vips_type_array_int, Vips.ArrayInt.new, value)
        value = self.arrayize(vips_type_array_double, Vips.ArrayDouble.new, value)
        value = self.arrayize(vips_type_array_image, Vips.ArrayImage.new, value)

        # blob-ize
        if GObject.type_is_a(self.prop.value_type, vips_type_blob):
            if not isinstance(value, Vips.Blob):
                value = Vips.Blob.new(None, value)

        # MODIFY input images need to be copied before assigning them
        if self.flags & Vips.ArgumentFlags.MODIFY:
            print 'taking copy of MODIFY image arg'
            value = value.copy()

        logging.debug('assigning %s' % self.prop.value_type)

        self.op.props.__setattr__(self.name, value)

    def get_value(self):
        value = self.op.props.__getattribute__(self.name)

        logging.debug('read out %s from %s' % (value, self.name))

        # turn VipsBlobs into strings, VipsArrayDouble into lists etc.
        # FIXME ... this will involve a copy, we should use
        # buffer() instead
        if isunpack(value):
            value = value.get()

        return value

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

    # rescan args, op2 has changed
    args = [Argument(op2, x) for x in op2.props]
    args.sort(lambda a, b: a.priority - b.priority)

    # gather output args 
    out = []

    for x in args:
        # required output arg
        if x.flags & enm.OUTPUT and x.flags & enm.REQUIRED:
            out.append(x.get_value())

        # modified input arg ... this will get the result of the copy() we 
        # did above
        if x.flags & enm.INPUT and x.flags & enm.MODIFY:
            out.append(x.get_value())

    # find all optional output args 
    optional_output = [x.name for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    for x in optional.keys():
        if x in optional_output:
            out.append(x.get_value())

    if len(out) == 1:
        out = out[0]
    elif len(out) == 0:
        out = None

    # unref everything now we have refs to all outputs we want
    op2.unref_outputs()

    logging.debug('success')

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

# this is a class method
def vips_image_new_from_buffer(cls, data, option_string, **kwargs):
    loader = Vips.Foreign.find_load_buffer(data)
    if loader == None:
        raise Error('No known loader for buffer.')
    logging.debug('Image.new_from_buffer: loader = %s' % loader)

# this is a class method
def vips_image_new_from_array(cls, array, scale = 1, offset = 0):
    # we accept a 1D array and assume height == 1, or a 2D array and check all
    # lines are the same length
    if not isinstance(array, list):
        raise TypeError('new_from_array() takes a list argument')
    if not isinstance(array[0], list):
        height = 1
        width = len(array)
    else:
        flat_array = array[0]
        height = len(array)
        width = len(array[0])
        for i in range(1, height):
            if len(array[i]) != width:
                raise TypeError('new_from_array() array not rectangular')
            flat_array += array[i]
        array = flat_array

    image = cls.new_matrix_from_array(width, height, array)

    # be careful to set them as double
    image.set('scale', float(scale))
    image.set('offset', float(offset))

    return image

def vips_image_getattr(self, name):
    logging.debug('Image.__getattr__ %s' % name)

    # look up in props first, eg. x.props.width
    if name in dir(self.props):
        return getattr(self.props, name)

    # 'format' is a reserved word, annoying, have bandfmt as an alias
    if name == 'bandfmt':
        return getattr(self.props, 'format')

    return lambda *args, **kwargs: _call_instance(self, name, args, kwargs)

def vips_image_write_to_file(self, vips_filename, **kwargs):
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    saver = Vips.Foreign.find_save(filename)
    if saver == None:
        raise Error('No known saver for "%s".' % filename)
    logging.debug('Image.write_to_file: saver = %s' % saver)

    _call_base(saver, [filename], kwargs, self, option_string)

def vips_image_write_to_buffer(self, vips_filename, **kwargs):
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    saver = Vips.Foreign.find_save_buffer(filename)
    if saver == None:
        raise Error('No known saver for "%s".' % filename)
    logging.debug('Image.write_to_buffer: saver = %s' % saver)

    return _call_base(saver, [], kwargs, self, option_string)

def vips_bandsplit(self):
    return [self.extract_band(i) for i in range(0, self.bands)]

# apply a function to a thing, or map over a list
# we often need to do something like (1.0 / other) and need to work for lists
# as well as scalars
def smap(func, x):
    if isinstance(x, list):
        return map(func, x)
    else:
        return func(x)

def vips_add(self, other):
    if isinstance(other, Vips.Image):
        return self.add(other)
    else:
        return self.linear(1, other)

def vips_sub(self, other):
    if isinstance(other, Vips.Image):
        return self.subtract(other)
    else:
        return self.linear(1, smap(lambda x: -1 * x, other))

def vips_rsub(self, other):
    return self.linear(-1, other)

def vips_mul(self, other):
    if isinstance(other, Vips.Image):
        return self.multiply(other)
    else:
        return self.linear(other, 0)

def vips_div(self, other):
    if isinstance(other, Vips.Image):
        return self.divide(other)
    else:
        return self.linear(smap(lambda x: 1.0 / x, other), 0)

def vips_rdiv(self, other):
    return (self ** -1) * other

def vips_floor(self):
    return self.round(Vips.OperationRound.FLOOR)

def vips_floordiv(self, other):
    if isinstance(other, Vips.Image):
        return self.divide(other).floor()
    else:
        return self.linear(smap(lambda x: 1.0 / x, other), 0).floor()

def vips_rfloordiv(self, other):
    return ((self ** -1) * other).floor()

def vips_mod(self, other):
    if isinstance(other, Vips.Image):
        return self.remainder(other)
    else:
        return self.remainder_const(other)

def vips_pow(self, other):
    if isinstance(other, Vips.Image):
        return self.math2(other, Vips.OperationMath2.POW)
    else:
        return self.math2_const(other, Vips.OperationMath2.POW)

def vips_rpow(self, other):
    return self.math2_const(other, Vips.OperationMath2.WOP)

def vips_lshift(self, other):
    if isinstance(other, Vips.Image):
        return self.boolean(other, Vips.OperationBoolean.LSHIFT)
    else:
        return self.boolean_const(other, Vips.OperationBoolean.LSHIFT)

def vips_rshift(self, other):
    if isinstance(other, Vips.Image):
        return self.boolean(other, Vips.OperationBoolean.RSHIFT)
    else:
        return self.boolean_const(other, Vips.OperationBoolean.RSHIFT)

def vips_and(self, other):
    if isinstance(other, Vips.Image):
        return self.boolean(other, Vips.OperationBoolean.AND)
    else:
        return self.boolean_const(other, Vips.OperationBoolean.AND)

def vips_or(self, other):
    if isinstance(other, Vips.Image):
        return self.boolean(other, Vips.OperationBoolean.OR)
    else:
        return self.boolean_const(other, Vips.OperationBoolean.OR)

def vips_xor(self, other):
    if isinstance(other, Vips.Image):
        return self.boolean(other, Vips.OperationBoolean.EOR)
    else:
        return self.boolean_const(other, Vips.OperationBoolean.EOR)

def vips_neg(self):
    return -1 * self

def vips_pos(self):
    return self

def vips_abs(self):
    return self.abs()

def vips_invert(self):
    return self ^ -1

def vips_real(self):
        return self.complexget(Vips.OperationComplexget.REAL)

def vips_imag(self):
        return self.complexget(Vips.OperationComplexget.IMAG)

def vips_polar(self):
        return self.complex(Vips.OperationComplex.POLAR)

def vips_rect(self):
        return self.complex(Vips.OperationComplex.RECT)

def vips_conj(self):
        return self.complex(Vips.OperationComplex.CONJ)

# paste our methods into Vips.Image

# class methods
setattr(Vips.Image, 'new_from_file', classmethod(vips_image_new_from_file))
setattr(Vips.Image, 'new_from_buffer', classmethod(vips_image_new_from_buffer))
setattr(Vips.Image, 'new_from_array', classmethod(vips_image_new_from_array))

# Search for all VipsOperation which don't have an input image object ... these
# become class methods

def vips_image_class_method(name, args, kwargs):
    logging.debug('vips_image_class_method %s' % name)

    # the first arg is the class we are called from ... drop it
    args = tuple(list(args)[1::])

    return _call_base(name, args, kwargs)

def define_class_methods(cls):
    if not cls.is_abstract():
        op = Vips.Operation.new(cls.name)

        found = False
        for prop in op.props:
            flags = op.get_argument_flags(prop.name)
            if flags & Vips.ArgumentFlags.INPUT and flags & Vips.ArgumentFlags.REQUIRED:
                if GObject.type_is_a(vips_type_image, prop.value_type):
                    found = True
                    break

        if not found:
            gtype = Vips.type_find("VipsOperation", cls.name)
            nickname = Vips.nickname_find(gtype)
            logging.debug('adding %s as a class method' % nickname)
            method = lambda *args, **kwargs: vips_image_class_method( nickname, args, kwargs)
            setattr(Vips.Image, nickname, classmethod(method))

    if len(cls.children) > 0:
        for child in cls.children:
            # not easy to get at the deprecated flag in an abtract type?
            if cls.name != 'VipsWrap7':
                define_class_methods(child)

define_class_methods(vips_type_operation)

# instance methods
Vips.Image.write_to_file = vips_image_write_to_file
Vips.Image.write_to_buffer = vips_image_write_to_buffer
# we can use Vips.Image.write_to_memory() directly

# a few useful things
Vips.Image.floor = vips_floor
Vips.Image.bandsplit = vips_bandsplit
Vips.Image.real = vips_real
Vips.Image.imag = vips_imag
Vips.Image.polar = vips_polar
Vips.Image.rect = vips_rect
Vips.Image.conj = vips_conj

# operator overloads
Vips.Image.__getattr__ = vips_image_getattr
Vips.Image.__add__ = vips_add
Vips.Image.__radd__ = vips_add
Vips.Image.__sub__ = vips_sub
Vips.Image.__rsub__ = vips_rsub
Vips.Image.__mul__ = vips_mul
Vips.Image.__rmul__ = vips_mul
Vips.Image.__div__ = vips_div
Vips.Image.__rdiv__ = vips_rdiv
Vips.Image.__floordiv__ = vips_floordiv
Vips.Image.__rfloordiv__ = vips_rfloordiv
Vips.Image.__mod__ = vips_mod
Vips.Image.__pow__ = vips_pow
Vips.Image.__rpow__ = vips_rpow
Vips.Image.__lshift__ = vips_lshift
Vips.Image.__rshift__ = vips_rshift
Vips.Image.__and__ = vips_and
Vips.Image.__rand__ = vips_and
Vips.Image.__or__ = vips_or
Vips.Image.__ror__ = vips_or
Vips.Image.__xor__ = vips_xor
Vips.Image.__rxor__ = vips_xor
Vips.Image.__neg__ = vips_neg
Vips.Image.__pos__ = vips_pos
Vips.Image.__abs__ = vips_abs
Vips.Image.__invert__ = vips_invert

# the cast operators int(), long() and float() must return numeric types, so we
# can't define them for images

# Add other classes to Vips
Vips.Error = Error
Vips.Argument = Argument
Vips.call = call

