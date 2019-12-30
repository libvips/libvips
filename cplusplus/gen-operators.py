#!/usr/bin/env python

# This file generates the member definitions and declarations for all vips 
# operators.

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

import argparse

from pyvips import Introspect, Operation, GValue, Error, \
    ffi, gobject_lib, type_map, type_from_name, nickname_find, type_name

# TODO Move to pyvips.GValue
source_type = type_from_name('VipsSource')
target_type = type_from_name('VipsTarget')

# turn a GType into a C++ type
gtype_to_cpp = {
    GValue.gbool_type: 'bool',
    GValue.gint_type: 'int',
    GValue.gdouble_type: 'double',
    GValue.gstr_type: 'const char *',
    GValue.refstr_type: 'char *',
    GValue.gflags_type: 'int',
    GValue.image_type: 'VImage',
    source_type: 'VSource',
    target_type: 'VTarget',
    GValue.array_int_type: 'std::vector<int>',
    GValue.array_double_type: 'std::vector<double>',
    GValue.array_image_type: 'std::vector<VImage>',
    GValue.blob_type: 'VipsBlob *'
}

cplusplus_suffixes = ('*', '&')
cplusplus_keywords = ('case', 'switch')

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
    intro = Introspect.get(operation_name)

    required_output = [name for name in intro.required_output if name != intro.member_x]

    has_output = len(required_output) >= 1

    # Add a C++ style comment block with some additional markings (@param,
    # @return)
    if declaration_only:
        result = '\n/**\n * {}.'.format(intro.description.capitalize())

        for name in intro.method_args:
            result += '\n * @param {} {}.' \
                      .format(cppize(name), intro.details[name]['blurb'])

        if has_output:
            # skip the first element
            for name in required_output[1:]:
                result += '\n * @param {} {}.' \
                          .format(cppize(name), intro.details[name]['blurb'])

        result += '\n * @param options Optional options.'

        if has_output:
            result += '\n * @return {}.' \
                      .format(intro.details[required_output[0]]['blurb'])

        result += '\n */\n'
    else:
        result = '\n'

    if intro.member_x is None and declaration_only:
        result += 'static '
    if has_output:
        # the first output arg will be used as the result
        cpp_type = get_cpp_type(intro.details[required_output[0]]['type'])
        spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
        result += '{0}{1}'.format(cpp_type, spacing)
    else:
        result += 'void '

    if not declaration_only:
        result += 'VImage::'

    cplusplus_operation = operation_name
    if operation_name in cplusplus_keywords:
        cplusplus_operation += '_image'

    result += '{0}( '.format(cplusplus_operation)
    for name in intro.method_args:
        details = intro.details[name]
        gtype = details['type']
        cpp_type = get_cpp_type(gtype)
        spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
        result += '{0}{1}{2}, '.format(cpp_type, spacing, cppize(name))

    # output params are passed by reference
    if has_output:
        # skip the first element
        for name in required_output[1:]:
            details = intro.details[name]
            gtype = details['type']
            cpp_type = get_cpp_type(gtype)
            spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
            result += '{0}{1}*{2}, '.format(cpp_type, spacing, cppize(name))

    result += 'VOption *options {0})'.format('= 0 ' if declaration_only else '')

    # if no 'this' available, it's a class method and they are all const
    if intro.member_x is not None:
        result += ' const'

    if declaration_only:
        result += ';'

        return result

    result += '\n{\n'

    if has_output:
        # the first output arg will be used as the result
        name = required_output[0]
        cpp_type = get_cpp_type(intro.details[name]['type'])
        spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
        result += '    {0}{1}{2};\n\n'.format(cpp_type, spacing, cppize(name))

    result += '    call( "{0}",\n'.format(operation_name)
    result += '        (options ? options : VImage::option())'
    if intro.member_x is not None:
        result += '->\n'
        result += '            set( "{0}", *this )'.format(intro.member_x)

    all_required = intro.method_args

    if has_output:
        # first element needs to be passed by reference
        arg = cppize(required_output[0])
        result += '->\n'
        result += '            set( "{0}", &{1} )' \
                  .format(required_output[0], arg)

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

    result += '}'

    return result


def generate_operators(declarations_only=False):
    all_nicknames = []

    def add_nickname(gtype, a, b):
        nickname = nickname_find(gtype)
        try:
            # can fail for abstract types
            intro = Introspect.get(nickname)

            # we are only interested in non-deprecated operations
            if (intro.flags & _OPERATION_DEPRECATED) == 0:
                all_nicknames.append(nickname)
        except Error:
            pass

        type_map(gtype, add_nickname)

        return ffi.NULL

    type_map(type_from_name('VipsOperation'), add_nickname)

    # add 'missing' synonyms by hand
    all_nicknames.append('crop')

    # make list unique and sort
    all_nicknames = list(set(all_nicknames))
    all_nicknames.sort()

    for nickname in all_nicknames:
        print(generate_operation(nickname, declarations_only))


parser = argparse.ArgumentParser(description='C++ binding generator')
parser.add_argument('--gen', '-g',
                    default='cpp',
                    choices=['h', 'cpp'],
                    help='File to generate: h (headers) or cpp ' + \
                         '(implementations) (default: %(default)s)')

if __name__ == '__main__':
    args = parser.parse_args()

    generate_operators(args.gen == 'h')
