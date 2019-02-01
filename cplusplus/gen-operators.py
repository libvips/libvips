#!/usr/bin/env python

# This file generates the member definitions and declarations for all vips operators.
# It's in Python, since we use the whole of FFI.

# Regenerate the files with something like:
#
#   cd cplusplus
#   python gen-operators.py

# this needs pyvips
#
#   pip install --user pyvips

# Sample member declaration:
# VImage invert(VOption *options = 0) const;

# Sample member definition:
# VImage VImage::invert( VOption *options ) const
# {
#     VImage out;
#
#     call( "invert",
#         (options ? options : VImage::option())->
#             set( "in", *this )->
#             set( "out", &out ) );
#
#     return( out );
# }

import datetime

from pyvips import Image, Operation, GValue, Error, \
    ffi, gobject_lib, type_map, type_from_name, nickname_find, type_name

# turn a GType into a C++ type
gtype_to_cpp = {
    GValue.gbool_type: 'bool',
    GValue.gint_type: 'int',
    GValue.gdouble_type: 'double',
    GValue.gstr_type: 'char *',
    GValue.refstr_type: 'char *',
    GValue.gflags_type: 'int',
    GValue.gobject_type: 'char *',
    GValue.image_type: 'VImage',
    GValue.array_int_type: 'std::vector<int>',
    GValue.array_double_type: 'std::vector<double>',
    GValue.array_image_type: 'std::vector<VImage>',
    GValue.blob_type: 'VipsBlob *'
}

# values for VipsArgumentFlags
_REQUIRED = 1
_INPUT = 16
_OUTPUT = 32
_DEPRECATED = 64
_MODIFY = 128

# for VipsOperationFlags
_OPERATION_DEPRECATED = 8


def get_cpp_type(gtype):
    """Map a gtype to C++ type name we use to represent it.
    """
    if gtype in gtype_to_cpp:
        return gtype_to_cpp[gtype]

    fundamental = gobject_lib.g_type_fundamental(gtype)

    # enum params use the C name as their name
    if fundamental == GValue.genum_type:
        return type_name(gtype)

    if fundamental in gtype_to_cpp:
        return gtype_to_cpp[fundamental]

    return '<unknown type>'


# swap any '-' for '_'
def cppize(name):
    return name.replace('-', '_')


def generate_operation(operation_name, declaration_only=False):
    op = Operation.new_from_name(operation_name)

    # we are only interested in non-deprecated args
    args = [[name, flags] for name, flags in op.get_args()
            if not flags & _DEPRECATED]

    # find the first required input image arg, if any ... that will be self
    member_x = None
    for name, flags in args:
        if ((flags & _INPUT) != 0 and
                (flags & _REQUIRED) != 0 and
                op.get_typeof(name) == GValue.image_type):
            member_x = name
            break

    required_input = [name for name, flags in args
                      if (flags & _INPUT) != 0 and
                      (flags & _REQUIRED) != 0 and
                      name != member_x]

    required_output = [name for name, flags in args
                       if ((flags & _OUTPUT) != 0 and
                           (flags & _REQUIRED) != 0) or
                       ((flags & _INPUT) != 0 and
                        (flags & _REQUIRED) != 0 and
                        (flags & _MODIFY) != 0) and
                       name != member_x]

    has_output = len(required_output) >= 1

    # TODO: Should we output the operation description as comment?
    # if declaration_only:
    #     description = op.get_description()
    #
    #     result = '\n\n/*\n'
    #     result += '  ' + description[0].upper() + description[1:] + '.\n'
    #     result += '*/\n'
    # else:

    result = '\n'
    if member_x is None and declaration_only:
        result += 'static '
    if has_output:
        # the first output arg will be used as the result
        cpp_type = get_cpp_type(op.get_typeof(required_output[0]))
        spacing = '' if cpp_type.endswith('*') else ' '
        result += '{0}{1}'.format(cpp_type, spacing)
    else:
        result += 'void '

    if not declaration_only:
        result += 'VImage::'

    result += '{0}( '.format(operation_name)
    for name in required_input:
        gtype = op.get_typeof(name)
        cpp_type = get_cpp_type(gtype)
        spacing = '' if cpp_type.endswith('*') else ' '
        result += '{0}{1}{2}, '.format(cpp_type, spacing, cppize(name))

    # output params are passed by reference
    if has_output:
        # skip the first element
        for name in required_output[1:]:
            gtype = op.get_typeof(name)
            cpp_type = get_cpp_type(gtype)
            spacing = '' if cpp_type.endswith('*') else ' '
            result += '{0}{1}*{2}, '.format(cpp_type, spacing, cppize(name))

    result += 'VOption *options {0})'.format('= 0 ' if declaration_only else '')

    # if no 'this' available, it's a class method and they are all const
    if member_x is not None:
        result += ' const'

    if declaration_only:
        result += ';'

        return result

    result += '\n{\n'

    if has_output:
        # the first output arg will be used as the result
        name = required_output[0]
        cpp_type = get_cpp_type(op.get_typeof(name))
        spacing = '' if cpp_type.endswith('*') else ' '
        result += '    {0}{1}{2};\n\n'.format(cpp_type, spacing, cppize(name))

    result += '    call( "{0}",\n'.format(operation_name)
    result += '        (options ? options : VImage::option())'
    if member_x is not None:
        result += '->\n'
        result += '            set( "{0}", *this )'.format(member_x)

    all_required = required_input

    if has_output:
        # first element needs to be passed by reference
        arg = cppize(required_output[0])
        result += '->\n'
        result += '            set( "{0}", &{1} )'.format(required_output[0], arg)

        # append the remaining list
        all_required += required_output[1:]

    for name in all_required:
        arg = cppize(name)
        result += '->\n'
        result += '            set( "{0}", {1} )'.format(name, arg)

    result += ' );\n'

    if has_output:
        result += '\n'
        result += '    return( {0} );\n'.format(required_output[0])

    result += '}\n'

    return result


preamble = """// {0} for vips operations
// {1}
// this file is generated automatically, do not edit!
"""

now = datetime.datetime.now().strftime('%a %d %b %H:%M:%S %Y')


def generate_operators(filename, declarations_only=False):
    all_nicknames = []

    def add_nickname(gtype, a, b):
        nickname = nickname_find(gtype)
        try:
            # can fail for abstract types
            op = Operation.new_from_name(nickname)

            # we are only interested in non-deprecated operations
            if (op.get_flags() & _OPERATION_DEPRECATED) == 0:
                all_nicknames.append(nickname)
        except Error:
            pass

        type_map(gtype, add_nickname)

        return ffi.NULL

    type_map(type_from_name('VipsOperation'), add_nickname)

    # TODO: Should we add the 'missing' extract_area synonym by hand?
    # all_nicknames.append('crop')

    # make list unique and sort
    all_nicknames = list(set(all_nicknames))
    all_nicknames.sort()

    print('Generating {0} ...'.format(filename))

    with open(filename, 'w') as f:
        f.write(preamble.format('headers' if declarations_only else "bodies", now))

        for nickname in all_nicknames:
            f.write(generate_operation(nickname, declarations_only))

        f.write('\n')


generate_operators('vips-operators.cpp')
generate_operators('include/vips/vips-operators.h', True)
