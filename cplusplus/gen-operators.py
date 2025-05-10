#!/usr/bin/env python3

# This file generates the member definitions and declarations for all vips
# operators.

# this needs pyvips
#   pip install --user pyvips

# rebuild with:
#   meson compile -Cbuild vips-operators-header
#   meson compile -Cbuild vips-operators-source

# Sample member declaration:
# VImage invert(VOption *options = nullptr) const;

# Sample member definition:
# VImage
# VImage::invert(VOption *options) const
# {
#   VImage out;
#
# 	call("invert", (options ? options : VImage::option())
# 				->set("in", *this)
# 				->set("out", &out));
#
# 	return out;
# }

import argparse

from pyvips import Introspect, Operation, GValue, Error, \
    ffi, gobject_lib, type_map, type_from_name, nickname_find, type_name

# turn a GType into a C++ type
gtype_to_cpp = {
    GValue.gbool_type: 'bool',
    GValue.gint_type: 'int',
    GValue.gdouble_type: 'double',
    GValue.gstr_type: 'const char *',
    GValue.refstr_type: 'char *',
    GValue.image_type: 'VImage',
    GValue.source_type: 'VSource',
    GValue.target_type: 'VTarget',
    GValue.guint64_type: 'guint64',
    type_from_name('VipsInterpolate'): 'VInterpolate',
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
    """Map a gtype to the C++ type name we use to represent it.
    """
    if gtype in gtype_to_cpp:
        return gtype_to_cpp[gtype]

    fundamental = gobject_lib.g_type_fundamental(gtype)

    # enum/flag params use the C name as their name
    if fundamental == GValue.genum_type or fundamental == GValue.gflags_type:
        return type_name(gtype)

    if fundamental in gtype_to_cpp:
        return gtype_to_cpp[fundamental]

    return '<unknown type>'


# swap any '-' for '_'
def cppize(name):
    return name.replace('-', '_')


def generate_operation(operation_name, declaration_only=False, indent=''):
    intro = Introspect.get(operation_name)

    required_output = [name
        for name in intro.required_output if name != intro.member_x]

    # We are only interested in non-deprecated arguments
    optional_input = [name
        for name in intro.optional_input if intro.details[name]['flags'] & _DEPRECATED == 0]

    has_output = len(required_output) >= 1

    # Add a C++ style comment block with some additional markings (@param,
    # @return)
    if declaration_only:
        result = f'\n{indent}/**'
        result += f'\n{indent} * {intro.description.capitalize()}.'

        if len(optional_input) > 0:
            result += f'\n{indent} *'
            result += f'\n{indent} * **Optional parameters**'
            for name in optional_input:
                details = intro.details[name]
                result += f'\n{indent} *   - **{cppize(name)}** -- '
                result += f'{details["blurb"]}, '
                result += f'{get_cpp_type(details["type"])}.'
            result += f'\n{indent} *'

        for name in intro.method_args:
            details = intro.details[name]
            result += f'\n{indent} * @param {cppize(name)} {details["blurb"]}.'

        if has_output:
            # skip the first element
            for name in required_output[1:]:
                details = intro.details[name]
                result += f'\n{indent} * @param {cppize(name)} {details["blurb"]}.'

        result += f'\n{indent} * @param options Set of options.'

        if has_output:
            details = intro.details[required_output[0]]
            result += f'\n{indent} * @return {details["blurb"]}.'

        result += f'\n{indent} */\n'
        if intro.flags & _OPERATION_DEPRECATED:
            result += f'{indent}G_DEPRECATED\n'
    else:
        result = '\n'

    if intro.member_x is None and declaration_only:
        result += f'{indent}static '
    else:
        result += indent
    if has_output:
        # the first output arg will be used as the result
        cpp_type = get_cpp_type(intro.details[required_output[0]]['type'])
        result += f'{cpp_type}'
    else:
        cpp_type = 'void'
        result += cpp_type

    if declaration_only:
        result += '' if cpp_type.endswith(cplusplus_suffixes) else ' '
    else:
        result += '\nVImage::'

    cplusplus_operation = operation_name
    if operation_name in cplusplus_keywords:
        cplusplus_operation += '_image'

    result += f'{cplusplus_operation}('
    for name in intro.method_args:
        details = intro.details[name]
        gtype = details['type']
        cpp_type = get_cpp_type(gtype)
        spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
        result += f'{cpp_type}{spacing}{cppize(name)}, '

    # output params are passed by reference
    if has_output:
        # skip the first element
        for name in required_output[1:]:
            details = intro.details[name]
            gtype = details['type']
            cpp_type = get_cpp_type(gtype)
            spacing = '' if cpp_type.endswith(cplusplus_suffixes) else ' '
            result += f'{cpp_type}{spacing}*{cppize(name)}, '

    result += f'VOption *options{" = nullptr" if declaration_only else ""})'

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
        result += f'\t{cpp_type}{spacing}{cppize(name)};\n\n'

    result += f'\tcall("{operation_name}", (options ? options : VImage::option())'
    if intro.member_x is not None:
        result += f'\n\t\t\t->set("{intro.member_x}", *this)'

    all_required = intro.method_args

    if has_output:
        # first element needs to be passed by reference
        arg = cppize(required_output[0])
        result += f'\n\t\t\t->set("{required_output[0]}", &{arg})'

        # append the remaining list
        all_required += required_output[1:]

    for name in all_required:
        arg = cppize(name)
        result += f'\n\t\t\t->set("{name}", {arg})'

    result += ');\n'

    if has_output:
        result += f'\n'
        result += f'\treturn {required_output[0]};\n'

    result += '}'

    return result


def generate_operators(declarations_only=False):
    all_nicknames = []

    # hidden CLI savers needs to be excluded from the API
    hidden_savers = [
        'avifsave_target',
        'magicksave_bmp',
        'magicksave_bmp_buffer',
        'pbmsave_target',
        'pfmsave_target',
        'pgmsave_target',
        'pnmsave_target',
    ]

    def add_nickname(gtype, a, b):
        nickname = nickname_find(gtype)
        try:
            # can fail for abstract types
            _ = Introspect.get(nickname)

            all_nicknames.append(nickname)
        except Error:
            pass

        type_map(gtype, add_nickname)

        return ffi.NULL

    type_map(type_from_name('VipsOperation'), add_nickname)

    # add 'missing' synonyms by hand
    all_nicknames.append('crop')

    # make list unique and sort
    all_nicknames = list(set(all_nicknames) - set(hidden_savers))
    all_nicknames.sort()

    indent = '\t' if declarations_only else ''

    print(f'''{indent}// {'headers' if declarations_only else 'bodies'} for vips operations
{indent}// this file is generated automatically, do not edit!
{indent}// clang-format off''')

    for nickname in all_nicknames:
        print(generate_operation(nickname, declarations_only, indent))


parser = argparse.ArgumentParser(description='C++ binding generator')
parser.add_argument('--gen', '-g',
                    default='cpp',
                    choices=['h', 'cpp'],
                    help='File to generate: h (headers) or cpp ' + \
                         '(implementations) (default: %(default)s)')

if __name__ == '__main__':
    args = parser.parse_args()

    generate_operators(args.gen == 'h')
