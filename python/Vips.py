# -*- Mode: Python; py-indent-offset: 4 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

from __future__ import division

# overrides for pygobject gobject-introspection binding for libvips, tested 
# with python2.7 and python3.4

# copy this file to dist-packages/gi/overrides, eg.
# 
#   sudo cp Vips.py /usr/lib/python2.7/dist-packages/gi/overrides
#   sudo cp Vips.py /usr/lib/python3/dist-packages/gi/overrides
#
# Alternatively, build vips to another prefix, then copy Vips.py and Vips.pyc
# from $prefix/lib/python2.7/dist-packages/gi/overrides to /usr

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
import numbers

logger = logging.getLogger(__name__)

from gi.repository import GObject
from ..overrides import override
from ..module import get_introspection_module

Vips = get_introspection_module('Vips')

__all__ = []

# start up vips! 
# passing argv[0] helps vips find its data files on some platforms
Vips.init(sys.argv[0])

# need the gtypes for various vips types
vips_type_array_int = GObject.GType.from_name("VipsArrayInt")
vips_type_array_double = GObject.GType.from_name("VipsArrayDouble")
vips_type_array_image = GObject.GType.from_name("VipsArrayImage")
vips_type_blob = GObject.GType.from_name("VipsBlob")
vips_type_image = GObject.GType.from_name("VipsImage")
vips_type_operation = GObject.GType.from_name("VipsOperation")
vips_type_ref_string = GObject.GType.from_name("VipsRefString")

def is_2D(value):
    if not isinstance(value, list):
        return False

    for x in value:
        if not isinstance(x, list):
            return False

        if len(x) != len(value[0]):
            return False

    return True

def imageize(match_image, value):
    logger.debug('imageize match_image=%s, value=%s' % (match_image, value))

    # 2D arrays become array images
    if is_2D(value):
        return Vips.Image.new_from_array(value)

    # if there's nothing to match to, also make an array
    if match_image is None:
        return Vips.Image.new_from_array(value)

    # assume this is a pixel constant ... expand into an image using
    # match as a template
    pixel = (Vips.Image.black(1, 1) + value).cast(match_image.format)
    image = pixel.embed(0, 0, match_image.width, match_image.height,
                        extend = Vips.Extend.COPY)
    image = image.copy(interpretation = match_image.interpretation,
                       xres = match_image.xres,
                       yres = match_image.yres)
    return image

# we'd like to use memoryview to avoid copying things like ICC profiles, but
# unfortunately pygobject does not support this ... so for blobs we just use
# bytes(). 

unpack_types = [[Vips.Blob, lambda x: bytes(x.get())],
                [Vips.RefString, lambda x: x.get()],
                [Vips.ArrayDouble, lambda x: x.get()],
                [Vips.ArrayImage, lambda x: x.get()], 
                [Vips.ArrayInt, lambda x: x.get()]]
def unpack(value):
    for t, cast in unpack_types:
        if isinstance(value, t):
            return cast(value)

    return value

def array_image_new(array):
    match_image = next((x for x in array if isinstance(x, Vips.Image)), None)
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
            return cast(value)

    return value

def run_cmplx(fn, image):
    """Run a complex function on a non-complex image.

    The image needs to be complex, or have an even number of bands. The input
    can be int, the output is always float or double.
    """
    original_format = image.format

    if not Vips.band_format_iscomplex(image.format):
        if image.bands % 2 != 0:
            raise "not an even number of bands"

        if not Vips.band_format_isfloat(image.format):
            image = image.cast(Vips.BandFormat.FLOAT)

        if image.format == Vips.BandFormat.DOUBLE:
            new_format = Vips.BandFormat.DPCOMPLEX
        else:
            new_format = Vips.BandFormat.COMPLEX

        image = image.copy(format = new_format, bands = image.bands / 2)

    image = fn(image)

    if not Vips.band_format_iscomplex(original_format):
        if image.format == Vips.BandFormat.DPCOMPLEX:
            new_format = Vips.BandFormat.DOUBLE
        else:
            new_format = Vips.BandFormat.FLOAT

        image = image.copy(format = new_format, bands = image.bands * 2)

    return image

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

        logger.debug('Error %s %s', self.message, self.detail)

    def __str__(self):
        return '%s\n  %s' % (self.message, self.detail)

Vips.Error = Error

class Argument(object):
    def __init__(self, op, prop):
        self.op = op
        self.prop = prop
        self.name = re.sub("-", "_", prop.name)
        self.flags = op.get_argument_flags(self.name)
        self.priority = op.get_argument_priority(self.name)
        self.isset = op.argument_isset(self.name)

    def set_value(self, match_image, value):
        logger.debug('assigning %s to %s' % (value, self.name))
        logger.debug('%s needs a %s' % (self.name, self.prop.value_type))

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
            # don't use .copy(): we want to make a new pipeline with no
            # reference back to the old stuff ... this way we can free the
            # previous image earlier
            logger.debug('MODIFY argument: copying image')
            new_image = Vips.Image.new_memory()
            value.write(new_image)
            value = new_image

        logger.debug('assigning %s' % value)

        self.op.props.__setattr__(self.name, value)

    def get_value(self):
        value = self.op.props.__getattribute__(self.name)

        logger.debug('read out %s from %s' % (value, self.name))

        return unpack(value)

    def description(self):
        result = self.name
        result += " " * (10 - len(self.name)) + " -- " + self.prop.blurb
        result += ", " + self.prop.value_type.name

        return result

Vips.Argument = Argument

class Operation(Vips.Operation):

    # find all the args for this op, sort into priority order
    # remember to ignore deprecated ones
    def get_args(self):
        args = [Argument(self, x) for x in self.props]
        args = [y for y in args 
                if not y.flags & Vips.ArgumentFlags.DEPRECATED]
        args.sort(key = lambda x: x.priority)

        return args

Operation = override(Operation)
__all__.append('Operation')

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
    logger.debug('_call_base name=%s, required=%s optional=%s' % 
                  (name, required, optional))
    if self:
        logger.debug('_call_base self=%s' % self)
    if option_string:
        logger.debug('_call_base option_string = %s' % option_string)

    try:
        op = Vips.Operation.new(name)
    except TypeError as e:
        raise Error('No such operator.')
    if op.get_flags() & Vips.OperationFlags.DEPRECATED:
        raise Error('No such operator.', 'operator "%s" is deprecated' % name)

    # set str options first so the user can't override things we set
    # deliberately and break stuff
    if option_string:
        if op.set_from_string(option_string) != 0:
            raise Error('Bad arguments.')

    args = op.get_args()

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
    for key in list(optional.keys()):
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
    logger.debug('_call_base checking cache for op %s' % op)
    op2 = Vips.cache_operation_build(op)
    logger.debug('_call_base got op2 %s' % op2)
    if op2 == None:
        raise Error('Error calling operator %s.' % name)

    # rescan args if op2 is different from op
    if op2 != op:
        logger.debug('_call_base rescanning args')
        args = op2.get_args()
        optional_output = {x.name: x for x in args if x.flags & enm.OUTPUT and 
                           not x.flags & enm.REQUIRED}

    # gather output args 
    logger.debug('_call_base fetching required output args')
    out = []

    for x in args:
        # required output arg
        if x.flags & enm.OUTPUT and x.flags & enm.REQUIRED:
            out.append(x.get_value())

        # modified input arg ... this will get the memory image we made above
        if x.flags & enm.INPUT and x.flags & enm.MODIFY:
            out.append(x.get_value())

    logger.debug('_call_base fetching optional output args')
    out_dict = {}
    for x in list(optional.keys()):
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

    logger.debug('success')

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
    """Create a new Image from a filename.

    Extra optional arguments depend on the loader selected by libvips. See each
    loader for details. 
    """
    filename = Vips.filename_get_filename(vips_filename)
    option_string = Vips.filename_get_options(vips_filename)
    loader = Vips.Foreign.find_load(filename)
    if loader == None:
        raise Error('No known loader for "%s".' % filename)
    logger.debug('Image.new_from_file: loader = %s' % loader)

    return _call_base(loader, [filename], kwargs, None, option_string)

setattr(Vips.Image, 'new_from_file', vips_image_new_from_file)

@classmethod
def vips_image_new_from_buffer(cls, data, option_string, **kwargs):
    """Create a new Image from binary data in a string.

    data -- binary image data
    option_string -- optional arguments in string form

    option_string can be something like "page=10" to load the 10th page of a
    tiff file. You can also give load options as keyword arguments. 
    """
    loader = Vips.Foreign.find_load_buffer(data)
    if loader == None:
        raise Error('No known loader for buffer.')
    logger.debug('Image.new_from_buffer: loader = %s' % loader)

    return _call_base(loader, [data], kwargs, None, option_string)

setattr(Vips.Image, 'new_from_buffer', vips_image_new_from_buffer)

@classmethod
def vips_image_new_from_array(cls, array, scale = 1, offset = 0):
    """Create a new image from an array.

    The array argument can be a 1D array to create a height == 1 image, or a 2D
    array to make a 2D image. Use scale and offset to set the scale factor,
    handy for integer convolutions. 
    """
    # we accept a 1D array and assume height == 1, or a 2D array and check all
    # lines are the same length
    if not isinstance(array, list):
        raise TypeError('new_from_array() takes a list argument')
    if not isinstance(array[0], list):
        height = 1
        width = len(array)
    else:
        # must copy the first row, we don't want to modify the passed-in array
        flat_array = list(array[0])
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
    except TypeError as e:
        raise Error('No such operator.')
    if op.get_flags() & Vips.OperationFlags.DEPRECATED:
        raise Error('No such operator.', 'operator "%s" is deprecated' % name)

    # find all the args for this op, sort into priority order
    args = op.get_args()

    enm = Vips.ArgumentFlags

    # find all required, unassigned input args
    required_input = [x for x in args if x.flags & enm.INPUT and 
                      x.flags & enm.REQUIRED and 
                      not x.isset]

    optional_input = [x for x in args if x.flags & enm.INPUT and 
                      not x.flags & enm.REQUIRED and 
                      not x.isset]

    required_output = [x for x in args if x.flags & enm.OUTPUT and 
                       x.flags & enm.REQUIRED]

    optional_output = [x for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    # find the first required input image, if any ... we will be a member
    # function of this instance
    member_x = None
    for i in range(0, len(required_input)):
        x = required_input[i]
        if GObject.type_is_a(vips_type_image, x.prop.value_type):
            member_x = x
            break

    description = op.get_description()
    result = description[0].upper() + description[1:] + ".\n\n"
    result += "Usage:\n"

    result += "   " + ", ".join([x.name for x in required_output]) + " = "
    if member_x:
        result += member_x.name + "." + name + "("
    else:
        result += "Vips.Image." + name + "("
    result += ", ".join([x.name for x in required_input
                         if x != member_x])
    if len(optional_input) > 0:
        result += ", "
    result += ", ".join([x.name + " = " + x.prop.value_type.name 
                         for x in optional_input])
    result += ")\n"

    result += "Where:\n"
    for x in required_output:
        result += "   " + x.description() + "\n"

    for x in required_input:
        result += "   " + x.description() + "\n"

    if len(optional_input) > 0:
        result += "Keyword parameters:\n"
        for x in optional_input:
            result += "   " + x.description() + "\n"

    if len(optional_output) > 0:
        result += "Extra output options:\n"
        for x in optional_output:
            result += "   " + x.description() + "\n"

    return result

# apply a function to a thing, or map over a list
# we often need to do something like (1.0 / other) and need to work for lists
# as well as scalars
def smap(func, x):
    if isinstance(x, list):
        return list(map(func, x))
    else:
        return func(x)

# decorator to set docstring
def add_doc(value):
    def _doc(func):
        func.__doc__ = value
        return func
    return _doc

class Image(Vips.Image):
    # for constructors, see class methods above

    # output

    def write_to_file(self, vips_filename, **kwargs):
        """Write an Image to a file. 

        The filename can contain save options, for example
        "fred.tif[compression=jpeg]", or save options can be given as keyword
        arguments. Save options depend on the selected saver. 
        """
        filename = Vips.filename_get_filename(vips_filename)
        option_string = Vips.filename_get_options(vips_filename)
        saver = Vips.Foreign.find_save(filename)
        if saver == None:
            raise Error('No known saver for "%s".' % filename)
        logger.debug('Image.write_to_file: saver = %s' % saver)

        _call_base(saver, [filename], kwargs, self, option_string)

    def write_to_buffer(self, format_string, **kwargs):
        """Write an Image to memory.

        Return the image as a binary string, encoded in the selected format.
        Save options can be given in the format_string, for example
        ".jpg[Q=90]". Save options depend on the selected saver.
        """
        filename = Vips.filename_get_filename(format_string)
        option_string = Vips.filename_get_options(format_string)
        saver = Vips.Foreign.find_save_buffer(filename)
        if saver == None:
            raise Error('No known saver for "%s".' % filename)
        logger.debug('Image.write_to_buffer: saver = %s' % saver)

        return _call_base(saver, [], kwargs, self, option_string)

    # we can use Vips.Image.write_to_memory() directly

    # support with in the most trivial way
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        pass

    # operator overloads

    def __getattr__(self, name):
        logger.debug('Image.__getattr__ %s' % name)

        # look up in props first, eg. x.props.width
        if name in dir(self.props):
            return getattr(self.props, name)

        @add_doc(generate_docstring(name))
        def call_function(*args, **kwargs):
            return _call_instance(self, name, args, kwargs)

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

    # a / const has always been a float in vips, so div and truediv are the 
    # same
    def __div__(self, other):
        if isinstance(other, Vips.Image):
            return self.divide(other)
        else:
            return self.linear(smap(lambda x: 1.0 / x, other), 0)

    def __rdiv__(self, other):
        return (self ** -1) * other

    def __truediv__(self, other):
        return self.__div__(other)

    def __rtruediv__(self, other):
        return self.__rdiv__(other)

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
        # for == and != we need to allow comparison to None
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.EQUAL)
        elif isinstance(other, list):
            return self.relational_const(other, Vips.OperationRelational.EQUAL)
        elif isinstance(other, numbers.Number):
            return self.relational_const(other, Vips.OperationRelational.EQUAL)
        else:
            return False

    def __ne__(self, other):
        if isinstance(other, Vips.Image):
            return self.relational(other, Vips.OperationRelational.NOTEQ)
        elif isinstance(other, list):
            return self.relational_const(other, Vips.OperationRelational.NOTEQ)
        elif isinstance(other, numbers.Number):
            return self.relational_const(other, Vips.OperationRelational.NOTEQ)
        else:
            return False

    def __getitem__(self, arg):
        if isinstance(arg, slice):
            i = 0
            if arg.start != None:
                i = arg.start

            n = self.bands - i
            if arg.stop != None:
                if arg.stop < 0:
                    n = self.bands + arg.stop - i
                else:
                    n = arg.stop - i
        elif isinstance(arg, int):
            i = arg
            n = 1
        else:
            raise TypeError

        if i < 0:
            i = self.bands + i

        if i < 0 or i >= self.bands:
            raise IndexError

        return self.extract_band(i, n = n)

    def __call__(self, x, y):
        return self.getpoint(x, y)

    # the cast operators int(), long() and float() must return numeric types, 
    # so we can't define them for images

    # a few useful things

    def get_value(self, field):
        """Get a named item from an Image.

        Fetch an item of metadata and convert it to a Python-friendly format.
        For example, VipsBlob values will be converted to bytes().
        """
        value = self.get(field)

        logger.debug('read out %s from %s' % (value, self))

        return unpack(value)

    def set_value(self, field, value):
        """Set a named item on an Image.

        Values are converted from Python types to something libvips can swallow.
        For example, bytes() can be used to set VipsBlob fields. 
        """
        gtype = self.get_typeof(field)
        logger.debug('assigning %s to %s' % (value, self))
        logger.debug('%s needs a %s' % (self, gtype))

        # blob-ize
        if GObject.type_is_a(gtype, vips_type_blob):
            if not isinstance(value, Vips.Blob):
                value = Vips.Blob.new(None, value)

        # image-ize
        if GObject.type_is_a(gtype, vips_type_image):
            if not isinstance(value, Vips.Image):
                value = imageize(self, value)

        # array-ize some types, if necessary
        value = arrayize(gtype, value)

        self.set(field, value)

    def floor(self):
        """Return the largest integral value not greater than the argument."""
        return self.round(Vips.OperationRound.FLOOR)

    def ceil(self):
        """Return the smallest integral value not less than the argument."""
        return self.round(Vips.OperationRound.CEIL)

    def rint(self):
        """Return the nearest integral value."""
        return self.round(Vips.OperationRound.RINT)

    def bandand(self):
        """AND image bands together."""
        return self.bandbool(Vips.OperationBoolean.AND)

    def bandor(self):
        """OR image bands together."""
        return self.bandbool(Vips.OperationBoolean.OR)

    def bandeor(self):
        """EOR image bands together."""
        return self.bandbool(Vips.OperationBoolean.EOR)

    def bandsplit(self):
        """Split an n-band image into n separate images."""
        return [x for x in self]

    def bandjoin(self, other):
        """Append a set of images or constants bandwise."""
        if not isinstance(other, list):
            other = [other]

        # if [other] is all numbers, we can use bandjoin_const
        non_number = next((x for x in other 
                            if not isinstance(x, numbers.Number)), 
                           None)

        if non_number == None:
            return self.bandjoin_const(other)
        else:
            return Vips.Image.bandjoin([self] + other)

    def maxpos(self):
        """Return the coordinates of the image maximum."""
        v, opts = self.max(x = True, y = True)
        x = opts['x']
        y = opts['y']
        return v, x, y

    def minpos(self):
        """Return the coordinates of the image minimum."""
        v, opts = self.min(x = True, y = True)
        x = opts['x']
        y = opts['y']
        return v, x, y

    def real(self):
        """Return the real part of a complex image."""
        return self.complexget(Vips.OperationComplexget.REAL)

    def imag(self):
        """Return the imaginary part of a complex image."""
        return self.complexget(Vips.OperationComplexget.IMAG)

    def polar(self):
        """Return an image converted to polar coordinates."""
        return run_cmplx(lambda x: x.complex(Vips.OperationComplex.POLAR), self)

    def rect(self):
        """Return an image converted to rectangular coordinates."""
        return run_cmplx(lambda x: x.complex(Vips.OperationComplex.RECT), self)

    def conj(self):
        """Return the complex conjugate of an image."""
        return self.complex(Vips.OperationComplex.CONJ)

    def sin(self):
        """Return the sine of an image in degrees."""
        return self.math(Vips.OperationMath.SIN)

    def cos(self):
        """Return the cosine of an image in degrees."""
        return self.math(Vips.OperationMath.COS)

    def tan(self):
        """Return the tangent of an image in degrees."""
        return self.math(Vips.OperationMath.TAN)

    def asin(self):
        """Return the inverse sine of an image in degrees."""
        return self.math(Vips.OperationMath.ASIN)

    def acos(self):
        """Return the inverse cosine of an image in degrees."""
        return self.math(Vips.OperationMath.ACOS)

    def atan(self):
        """Return the inverse tangent of an image in degrees."""
        return self.math(Vips.OperationMath.ATAN)

    def log(self):
        """Return the natural log of an image."""
        return self.math(Vips.OperationMath.LOG)

    def log10(self):
        """Return the log base 10 of an image."""
        return self.math(Vips.OperationMath.LOG10)

    def exp(self):
        """Return e ** pixel."""
        return self.math(Vips.OperationMath.EXP)

    def exp10(self):
        """Return 10 ** pixel."""
        return self.math(Vips.OperationMath.EXP10)

    def erode(self, mask):
        """Erode with a structuring element."""
        return self.morph(mask, Vips.OperationMorphology.ERODE)

    def dilate(self, mask):
        """Dilate with a structuring element."""
        return self.morph(mask, Vips.OperationMorphology.DILATE)

    def median(self, size):
        """size x size median filter."""
        return self.rank(size, size, (size * size) / 2)

    def fliphor(self):
        """Flip horizontally."""
        return self.flip(Vips.Direction.HORIZONTAL)

    def flipver(self):
        """Flip vertically."""
        return self.flip(Vips.Direction.VERTICAL)

    def rot90(self):
        """Rotate 90 degrees clockwise."""
        return self.rot(Vips.Angle.D90)

    def rot180(self):
        """Rotate 180 degrees."""
        return self.rot(Vips.Angle.D180)

    def rot270(self):
        """Rotate 270 degrees clockwise."""
        return self.rot(Vips.Angle.D270)

    # we need different imageize rules for this operator ... we need to 
    # imageize th and el to match each other first
    @add_doc(generate_docstring("ifthenelse"))
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
                    "arrayjoin",
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
                    "magickload_buffer",
                    "fitsload",
                    "openexrload"]

def generate_class_method(name):
    @classmethod
    @add_doc(generate_docstring(name))
    def class_method(cls, *args, **kwargs):
        return _call_base(name, args, kwargs)

    return class_method

for nickname in class_methods:
    logger.debug('adding %s as a class method' % nickname)
    # some may be missing in this vips, eg. we might not have "webpload"
    try:
        method = generate_class_method(nickname)
        setattr(Vips.Image, nickname, method)
    except Error:
        pass

Image = override(Image)
__all__.append('Image')
