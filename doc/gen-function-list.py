#!/usr/bin/env python

# walk vips and generate a list of all operators and their descriptions
# for docs

# this needs pyvips
#
#   pip install --user pyvips

# sample output:

# <row>
#   <entry>gamma</entry>
#   <entry>Gamma an image</entry>
#   <entry>vips_gamma()</entry>
# </row>

from pyvips import Operation, Error, \
    ffi, type_map, type_from_name, nickname_find

# for VipsOperationFlags
_OPERATION_DEPRECATED = 8


def gen_function(operation_name):
    op = Operation.new_from_name(operation_name)

    print('<row>')
    print('  <entry>{}</entry>'.format(operation_name))
    print('  <entry>{}</entry>'.format(op.get_description().capitalize()))
    print('  <entry>vips_{}()</entry>'.format(operation_name))
    print('</row>')


def gen_function_list():
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

    # add 'missing' synonyms by hand
    all_nicknames.append('crop')

    # make list unique and sort
    all_nicknames = list(set(all_nicknames))
    all_nicknames.sort()

    for nickname in all_nicknames:
        gen_function(nickname)


if __name__ == '__main__':
    gen_function_list()
