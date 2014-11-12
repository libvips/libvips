# -*- Mode: Python; py-indent-offset: 4 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

# copy this file to /usr/lib/python2.7/dist-packages/gi/overrides/

# This file is part of VIPS.
# 
# VIPS is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
# more details.
# 
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
# 
# These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

import sys
import re
import logging

from gi.overrides import override
from gi.importer import modules
from gi.repository import GObject

Vips = modules['Vips']._introspection_module
__all__ = []

# start up vips!
Vips.init(sys.argv[0])

# need the gtypes for various vips types
vips_type_array_int = GObject.GType.from_name("VipsArrayInt")
vips_type_array_double = GObject.GType.from_name("VipsArrayDouble")
vips_type_array_image = GObject.GType.from_name("VipsArrayImage")
vips_type_blob = GObject.GType.from_name("VipsBlob")
vips_type_image = GObject.GType.from_name("VipsImage")
vips_type_operation = GObject.GType.from_name("VipsOperation")

def imageize(match_image, value):
    if match_image is None:
        return value

    pixel = (Vips.Image.black(1, 1) + value).cast(match_image.format)
    image = pixel.embed(0, 0, match_image.width, match_image.height,
                        extend = Vips.Extend.COPY)
    return image

unpack_types = [Vips.Blob, Vips.ArrayDouble, Vips.ArrayImage, Vips.ArrayInt]
def isunpack(obj):
    for t in unpack_types:
        if isinstance(obj, t):
            return True
    return False

def array_image_new(array):
    match_image = None
    for i in range(0, len(array)):
        if isinstance(array[i], Vips.Image):
            match_image = array[i]
            break

    if match_image is None:
        raise Error('Unable to make image array argument.', 
                    'Array must contain at least one image.')

    for i in range(0, len(array)):
        if not isinstance(array[i], Vips.Image):
            array[i] = imageize(match_image, array[i])

    return Vips.ArrayImage.new(array)

arrayize_types = [[vips_type_array_int, Vips.ArrayInt.new],
                  [vips_type_array_double, Vips.ArrayDouble.new],
                  [vips_type_array_image, array_image_new]]
def arrayize(gtype, value):
    for t, cast in arrayize_types:
        if GObject.type_is_a(gtype, t):
            if not isinstance(value, list):
                value = [value]
            value = cast(value)

    return value

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

        logging.debug('Error %s %s', self.message, self.detail)

    def __str__(self):
        return '%s\n  %s' % (self.message, self.detail)

Vips.Error = Error

class Argument:
    def __init__(self, op, prop):
        self.op = op;
        self.prop = prop;
        self.name = re.sub("-", "_", prop.name);
        self.flags = op.get_argument_flags(self.name)
        self.priority = op.get_argument_priority(self.name)
        self.isset = op.argument_isset(self.name)

    def set_value(self, match_image, value):
        logging.debug('assigning %s to %s' % (value, self.name))
        logging.debug('%s needs a %s' % (self.name, self.prop.value_type))

        # blob-ize
        if GObject.type_is_a(self.prop.value_type, vips_type_blob):
            if not isinstance(value, Vips.Blob):
                value = Vips.Blob.new(None, value)

        # image-ize
        if GObject.type_is_a(self.prop.value_type, vips_type_image):
            if not isinstance(value, Vips.Image):
                value = imageize(match_image, value)

        # array-ize some types, if necessary
        value = arrayize(self.prop.value_type, value)

        # MODIFY input images need to be copied before assigning them
        if self.flags & Vips.ArgumentFlags.MODIFY:
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

Vips.Argument = Argument

# search a list recursively for a Vips.Image object
def find_image(x):
    if isinstance(x, Vips.Image):
        return x
    if isinstance(x, list):
        for i in x:
            y = find_image(i)
            if y is not None:
                return y
    return None

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
    if self is not None:
        found = False
        for x in required_input:
            if GObject.type_is_a(self, x.prop.value_type):
                x.set_value(None, self)
                required_input.remove(x)
                found = True
                break

        if not found:
            raise Error('Bad arguments.', 'No %s argument to %s.' %
                        (str(self.__class__), name))

    if len(required_input) != len(required):
        raise Error('Wrong number of arguments.', 
                    '%s needs %d arguments, you supplied %d.' % 
                    (name, len(required_input), len(required)))

    # if we need an image arg but the user supplied a number or list of 
    # numbers, we expand it into an image automatically ... the number is
    # expanded to match self, or if that's None, the first image we can find in
    # the required or optional arguments
    match_image = self
    if match_image is None:
        for arg in required:
            match_image = find_image(arg)
            if match_image is not None:
                break

    if match_image is None:
        for arg_name in optional:
            match_image = find_image(optional[arg_name])
            if match_image is not None:
                break

    for i in range(len(required_input)):
        required_input[i].set_value(match_image, required[i])

    # find all optional, unassigned input args ... make a hash from name to
    # Argument
    optional_input = {x.name: x for x in args if x.flags & enm.INPUT and 
                      not x.flags & enm.REQUIRED and 
                      not x.isset}

    # find all optional output args ... we use "x = True" 
    # in args to mean add that to output
    optional_output = {x.name: x for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED}

    # set optional input args
    for key in optional.keys():
        if key in optional_input:
            optional_input[key].set_value(match_image, optional[key])
        elif key in optional_output:
            # must be a literal True value
            if optional[key] is not True:
                raise Error('Optional output argument must be True.',
                            'Argument %s should equal True.' % key)
        else:
            raise Error('Unknown argument.', 
                        'Operator %s has no argument %s.' % (name, key))

    # call
    op2 = Vips.cache_operation_build(op)
    if op2 == None:
        raise Error('Error calling operator %s.' % name)

    # rescan args if op2 is different from op
    if op2 != op:
        args = [Argument(op2, x) for x in op2.props]
        args.sort(lambda a, b: a.priority - b.priority)
        optional_output = {x.name: x for x in args if x.flags & enm.OUTPUT and 
                           not x.flags & enm.REQUIRED}

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

    out_dict = {}
    for x in optional.keys():
        if x in optional_output:
            out_dict[x] = optional_output[x].get_value()
    if out_dict != {}:
        out.append(out_dict)

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

Vips.call = call

# here from getattr ... try to run the attr as a method
def _call_instance(self, name, args, kwargs):
    return _call_base(name, args, kwargs, self)

@classmethod
def vips_image_new_from_file(cls, vips_filename, **kwargs):
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    loader = Vips.Foreign.find_load(filename)
    if loader == None:
        raise Error('No known loader for "%s".' % filename)
    logging.debug('Image.new_from_file: loader = %s' % loader)

    return _call_base(loader, [filename], kwargs, None, option_string)

setattr(Vips.Image, 'new_from_file', vips_image_new_from_file)

@classmethod
def vips_image_new_from_buffer(cls, data, option_string, **kwargs):
    loader = Vips.Foreign.find_load_buffer(data)
    if loader == None:
        raise Error('No known loader for buffer.')
    logging.debug('Image.new_from_buffer: loader = %s' % loader)

setattr(Vips.Image, 'new_from_buffer', vips_image_new_from_buffer)

@classmethod
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

setattr(Vips.Image, 'new_from_array', vips_image_new_from_array)

def generate_docstring(name):
    try:
        op = Vips.Operation.new(name)
    except TypeError, e:
        return 'No such operator ' + name

    # find all the args for this op, sort into priority order
    args = [Argument(op, x) for x in op.props]
    args.sort(lambda a, b: a.priority - b.priority)

    enm = Vips.ArgumentFlags

    # find all required, unassigned input args
    required_input = [x for x in args if x.flags & enm.INPUT and 
                      x.flags & enm.REQUIRED and 
                      not x.isset]

    optional_input = [x for x in args if x.flags & enm.INPUT and 
                      not x.flags & enm.REQUIRED and 
                      not x.isset]

    required_output = [x for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    optional_output = [x for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    result = "usage:\n"

    for x in required_input:
        result += x.name + "\n"

    return result

# apply a function to a thing, or map over a list
# we often need to do something like (1.0 / other) and need to work for lists
# as well as scalars
def smap(func, x):
    if isinstance(x, list):
        return map(func, x)
    else:
        return func(x)

class Image(Vips.Image):
    """This is a test docstring in Vips.py ... does this get attached to the 
       class we are overriding?
    """

    # constructors, see class methods above

    def __init__(self):
        Vips.Image.__init__(self)

    # output

    def write_to_file(self, vips_filename, **kwargs):
        filename = Vips.filename_get_filename(vips_filename)
        option_string = Vips.filename_get_options(vips_filename)
        saver = Vips.Foreign.find_save(filename)
        if saver == None:
            raise Error('No known saver for "%s".' % filename)
        logging.debug('Image.write_to_file: saver = %s' % saver)

        _call_base(saver, [filename], kwargs, self, option_string)

    def write_to_buffer(self, vips_filename, **kwargs):
        filename = Vips.filename_get_filename(vips_filename)
        option_string = Vips.filename_get_options(vips_filename)
        saver = Vips.Foreign.find_save_buffer(filename)
        if saver == None:
            raise Error('No known saver for "%s".' % filename)
        logging.debug('Image.write_to_buffer: saver = %s' % saver)

        return _call_base(saver, [], kwargs, self, option_string)

    # we can use Vips.Image.write_to_memory() directly

    # operator overloads

    def __getattr__(self, name):
        logging.debug('Image.__getattr__ %s' % name)

        # look up in props first, eg. x.props.width
        if name in dir(self.props):
            return getattr(self.props, name)

        def call_function(*args, **kwargs):
            return _call_instance(self, name, args, kwargs)
        call_function.__doc__ = generate_docstring(name)

        return call_function

    def __add__(self, other):
        if isinstance(other, Vips.Image):
            return self.add(other)
        else:
            return self.linear(1, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, Vips.Image):
            return self.subtract(other)
        else:
            return self.linear(1, smap(lambda x: -1 * x, other))

    def __rsub__(self, other):
        return self.linear(-1, other)

    def __mul__(self, other):
        if isinstance(other, Vips.Image):
            return self.multiply(other)
        else:
            return self.linear(other, 0)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __div__(self, other):
        if isinstance(other, Vips.Image):
            return self.divide(other)
        else:
            return self.linear(smap(lambda x: 1.0 / x, other), 0)

    def __rdiv__(self, other):
        return (self ** -1) * other

    def __floordiv__(self, other):
        if isinstance(other, Vips.Image):
            return self.divide(other).floor()
        else:
            return self.linear(smap(lambda x: 1.0 / x, other), 0).floor()

    def __rfloordiv__(self, other):
        return ((self ** -1) * other).floor()

    def __mod__(self, other):
        if isinstance(other, Vips.Image):
            return self.remainder(other)
        else:
            return self.remainder_const(other)

    def __pow__(self, other):
        if isinstance(other, Vips.Image):
            return self.math2(other, Vips.OperationMath2.POW)
        else:
            return self.math2_const(other, Vips.OperationMath2.POW)

    def __rpow__(self, other):
        return self.math2_const(other, Vips.OperationMath2.WOP)

    def __abs__(self):
        return self.abs()

    def __lshift__(self, other):
        if isinstance(other, Vips.Image):
            return self.boolean(other, Vips.OperationBoolean.LSHIFT)
        else:
            return self.boolean_const(other, Vips.OperationBoolean.LSHIFT)

    def __rshift__(self, other):
        if isinstance(other, Vips.Image):
            return self.boolean(other, Vips.OperationBoolean.RSHIFT)
        else:
            return self.boolean_const(other, Vips.OperationBoolean.RSHIFT)

    def __and__(self, other):
        if isinstance(other, Vips.Image):
            return self.boolean(other, Vips.OperationBoolean.AND)
        else:
            return self.boolean_const(other, Vips.OperationBoolean.AND)

    def __rand__(self, other):
        return self.__and__(other)

    def __or__(self, other):
        if isinstance(other, Vips.Image):
            return self.boolean(other, Vips.OperationBoolean.OR)
        else:
            return self.boolean_const(other, Vips.OperationBoolean.OR)

    def __ror__(self, other):
        return self.__or__(other)

    def __xor__(self, other):
        if isinstance(other, Vips.Image):
            return self.boolean(other, Vips.OperationBoolean.EOR)
        else:
            return self.boolean_const(other, Vips.OperationBoolean.EOR)

    def __rxor__(self, other):
        return self.__xor__(other)

    def __neg__(self):
        return -1 * self

    def __pos__(self):
        return self

    def __invert__(self):
        return self ^ -1

    def __gt__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.MORE)
        else:
            return self.relational_const(other, Vips.OperationRelational.MORE)

    def __ge__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.MOREEQ)
        else:
            return self.relational_const(other, Vips.OperationRelational.MOREEQ)

    def __lt__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.LESS)
        else:
            return self.relational_const(other, Vips.OperationRelational.LESS)

    def __le__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.LESSEQ)
        else:
            return self.relational_const(other, Vips.OperationRelational.LESSEQ)

    def __eq__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.EQUAL)
        else:
            return self.relational_const(other, Vips.OperationRelational.EQUAL)

    def __ne__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.NOTEQ)
        else:
            return self.relational_const(other, Vips.OperationRelational.NOTEQ)

    # the cast operators int(), long() and float() must return numeric types, 
    # so we can't define them for images

    # a few useful things

    def get_value(self, field):
        value = self.get(field)

        logging.debug('read out %s from %s' % (value, self))

        # turn VipsBlobs into strings, VipsArrayDouble into lists etc.
        # FIXME ... this will involve a copy, we should use
        # buffer() instead
        if isunpack(value):
            value = value.get()

        return value

    def set_value(self, field, value):
        gtype = self.get_typeof(field)
        logging.debug('assigning %s to %s' % (value, self))
        logging.debug('%s needs a %s' % (self, gtype))

        # blob-ize
        if GObject.type_is_a(gtype, vips_type_blob):
            if not isinstance(value, Vips.Blob):
                value = Vips.Blob.new(None, value)

        # image-ize
        if GObject.type_is_a(gtype, vips_type_image):
            if not isinstance(value, Vips.Image):
                value = imageize(match_image, value)

        # array-ize some types, if necessary
        value = arrayize(gtype, value)

        self.set(field, value)

    def floor(self):
        return self.round(Vips.OperationRound.FLOOR)

    def ceil(self):
        return self.round(Vips.OperationRound.CEIL)

    def rint(self):
        return self.round(Vips.OperationRound.RINT)

    def bandsplit(self):
        return [self.extract_band(i) for i in range(0, self.bands)]

    def bandjoin(self, other):
        if not isinstance(other, list):
            other = [other]

        return Vips.Image.bandjoin([self] + other)

    def maxpos(self):
        v, opts = self.max(x = True, y = True)
        x = opts['x']
        y = opts['y']
        return v, x, y

    def minpos(self):
        v, opts = self.min(x = True, y = True)
        x = opts['x']
        y = opts['y']
        return v, x, y

    def real(self):
        return self.complexget(Vips.OperationComplexget.REAL)

    def imag(self):
        return self.complexget(Vips.OperationComplexget.IMAG)

    def polar(self):
        return self.complex(Vips.OperationComplex.POLAR)

    def rect(self):
        return self.complex(Vips.OperationComplex.RECT)

    def conj(self):
        return self.complex(Vips.OperationComplex.CONJ)

    def sin(self):
        return self.math(Vips.OperationMath.SIN)

    def cos(self):
        return self.math(Vips.OperationMath.COS)

    def tan(self):
        return self.math(Vips.OperationMath.TAN)

    def asin(self):
        return self.math(Vips.OperationMath.ASIN)

    def acos(self):
        return self.math(Vips.OperationMath.ACOS)

    def atan(self):
        return self.math(Vips.OperationMath.ATAN)

    def log(self):
        return self.math(Vips.OperationMath.LOG)

    def log10(self):
        return self.math(Vips.OperationMath.LOG10)

    def exp(self):
        return self.math(Vips.OperationMath.EXP)

    def exp10(self):
        return self.math(Vips.OperationMath.EXP10)

    # we need different imageize rules for this operator ... we need to 
    # imageize th and el to match each other first
    def ifthenelse(self, th, el, **kwargs):
        for match_image in [th, el, self]:
            if isinstance(match_image, Vips.Image):
                break

        if not isinstance(th, Vips.Image):
            th = imageize(match_image, th)
        if not isinstance(el, Vips.Image):
            el = imageize(match_image, el)

        return _call_base("ifthenelse", [th, el], kwargs, self)

# add operators which needs to be class methods

# use find_class_methods.py to generate this list

class_methods = [
                    "system",
                    "sum",
                    "bandjoin",
                    "bandrank",
                    "black",
                    "gaussnoise",
                    "text",
                    "xyz",
                    "gaussmat",
                    "logmat",
                    "eye",
                    "grey",
                    "zone",
                    "sines",
                    "mask_ideal",
                    "mask_ideal_ring",
                    "mask_ideal_band",
                    "mask_butterworth",
                    "mask_butterworth_ring",
                    "mask_butterworth_band",
                    "mask_gaussian",
                    "mask_gaussian_ring",
                    "mask_gaussian_band",
                    "mask_fractal",
                    "tonelut",
                    "identity",
                    "fractsurf",
                    "radload",
                    "ppmload",
                    "csvload",
                    "matrixload",
                    "analyzeload",
                    "rawload",
                    "vipsload",
                    "pngload",
                    "pngload_buffer",
                    "matload",
                    "jpegload",
                    "jpegload_buffer",
                    "webpload",
                    "webpload_buffer",
                    "tiffload",
                    "tiffload_buffer",
                    "openslideload",
                    "magickload",
                    "fitsload",
                    "openexrload"]

def add_doc(value):
    def _doc(func):
        func.__doc__ = value
        return func
    return _doc

def generate_class_method(name):
    @classmethod
    @add_doc(generate_docstring(name))
    def class_method(cls, *args, **kwargs):
        return _call_base(name, args, kwargs)

    return class_method

for nickname in class_methods:
    logging.debug('adding %s as a class method' % nickname)
    method = generate_class_method(nickname)
    setattr(Vips.Image, nickname, method)

Image = override(Image)
__all__.append('Image')
