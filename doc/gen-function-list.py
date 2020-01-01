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

from pyvips import Introspect, Operation, Error, \
    ffi, type_map, type_from_name, nickname_find

# for VipsOperationFlags
_OPERATION_DEPRECATED = 8


def gen_function(operation_name, overloads):
    intro = Introspect.get(operation_name)

    c_operations = 'vips_{}()'.format(operation_name)

    if overloads:
        c_operations += ', ' + (', '.join('vips_{}()'.format(n) for n in overloads))

    result = '<row>\n'
    result += '  <entry>{}</entry>\n'.format(operation_name)
    result += '  <entry>{}</entry>\n'.format(intro.description.capitalize())
    result += '  <entry>{}</entry>\n'.format(c_operations)
    result += '</row>'

    return result


def gen_function_list():
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

    # make list unique and sort
    all_nicknames = list(set(all_nicknames))
    all_nicknames.sort()

    # make dict with overloads
    overloads = {
        'bandbool': ['bandand', 'bandor', 'bandeor', 'bandmean'],
        'bandjoin': ['bandjoin2'],
        'bandjoin_const': ['bandjoin_const1'],
        'boolean': ['andimage', 'orimage', 'eorimage', 'lshift', 'rshift'],
        'cast': ['cast_uchar', 'cast_char', 'cast_ushort', 'cast_short' 'cast_uint', 'cast_int', 'cast_float',
                 'cast_double', 'cast_complex', 'cast_dpcomplex'],
        'complex': ['polar', 'rect', 'conj'],
        'complex2': ['cross_phase'],
        'complexget': ['real', 'imag'],
        'draw_circle': ['draw_circle1'],
        'draw_flood': ['draw_flood1'],
        'draw_line': ['draw_line1'],
        'draw_mask': ['draw_mask1'],
        'draw_rect': ['draw_rect1', 'draw_point', 'draw_point1'],
        'extract_area': ['crop'],
        'linear': ['linear1'],
        'math': ['sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'exp', 'exp10', 'log', 'log10'],
        'math2': ['pow', 'wop'],
        'rank': ['median'],
        'relational': ['equal', 'notequal', 'less', 'lesseq', 'more', 'moreeq'],
        'remainder_const': ['remainder_const1'],
        'round': ['floor', 'ceil', 'rint'],
    }

    overloads['boolean_const'] = [o + '_const' for o in overloads['boolean']] + ['boolean_const1'] + \
                                 [o + '_const1' for o in overloads['boolean']]

    overloads['math2_const'] = [o + '_const' for o in overloads['boolean']] + ['math2_const1'] + \
                               [o + '_const1' for o in overloads['boolean']]

    overloads['relational_const'] = [o + '_const' for o in overloads['relational']] + ['relational_const1'] + \
                                    [o + '_const1' for o in overloads['relational']]

    for nickname in all_nicknames:
        result = gen_function(nickname, overloads[nickname] if nickname in overloads else None)
        print(result)


if __name__ == '__main__':
    gen_function_list()
