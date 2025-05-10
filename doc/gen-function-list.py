#!/usr/bin/env python3

# walk vips and generate a list of all operators and their descriptions
# for docs

# this needs pyvips
#   pip install --user pyvips

# rebuild with:
#   ./gen-function-list.py > function-list.md

# sample output:
# | `gamma` | Gamma an image | [method@Image.gamma] |

from pyvips import Introspect, Operation, Error, \
    ffi, type_map, type_from_name, nickname_find

# for VipsOperationFlags
_OPERATION_DEPRECATED = 8


def gen_function(operation_name, overloads):
    intro = Introspect.get(operation_name)

    # Keep-in-sync with fixup-gir-for-doc.py
    image_funcs = [
        'arrayjoin',
        'bandjoin',
        'bandrank',
        'composite',
        'sum',
        'switch',
    ]

    if operation_name in image_funcs:
        c_operations = f'[func@Image.{operation_name}]'
    else:
        operation_type = 'ctor' if intro.member_x is None else 'method'
        operation_class = 'Blob' if operation_name == 'profile_load' else 'Image'
        c_operations = f'[{operation_type}@{operation_class}.{operation_name}]'

    if overloads:
        c_operations += ', ' + (', '.join(f'[method@Image.{n}]' for n in overloads))

    result = f"| `{operation_name}` | {intro.description.capitalize()} | {c_operations} |"

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
        'cast': ['cast_uchar', 'cast_char', 'cast_ushort', 'cast_short',
            'cast_uint', 'cast_int', 'cast_float', 'cast_double', 
            'cast_complex', 'cast_dpcomplex'],
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
        'math': ['sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 
            'cosh', 'tanh', 'asinh', 'acosh', 'atanh', 'exp', 'exp10', 
            'log', 'log10'],
        'math2': ['pow', 'wop', 'atan2'],
        'rank': ['median'],
        'relational': ['equal', 'notequal', 'less', 'lesseq', 'more', 'moreeq'],
        'remainder_const': ['remainder_const1'],
        'round': ['floor', 'ceil', 'rint'],
    }

    overloads['boolean_const'] = \
            [o + '_const' for o in overloads['boolean']] \
            + ['boolean_const1'] \
            + [o + '_const1' for o in overloads['boolean']]

    overloads['math2_const'] = \
            [o + '_const' for o in overloads['boolean']] \
            + ['math2_const1'] \
            + [o + '_const1' for o in overloads['boolean']]

    overloads['relational_const'] = \
            [o + '_const' for o in overloads['relational']] \
            + ['relational_const1'] \
            + [o + '_const1' for o in overloads['relational']]

    for nickname in all_nicknames:
        result = gen_function(nickname, 
                overloads[nickname] if nickname in overloads else None)
        print(result)


if __name__ == '__main__':
    print("""Title: Operator index / Alphabetical

libvips has a set of operators, each of which computes some useful image
processing operation. Each operator is implemented as a [class@GObject.Object]
class, for example `VipsGamma`. Classes are identified by their unique
[property@VipsObject:nickname], in this case `gamma`.

From the command-line, C++ and most language bindings, you use the nickname
to call the operator. For example in C++:

```c++
vips::VImage fred = ...;
vips::VImage jim = fred.gamma();
```

or Python:

```python
fred = jim.gamma()
```

libvips has a set of C wrapper functions for calling operators, in this
case [method@Image.gamma]:

```c
VipsImage *fred = ...;
VipsImage *jim;

if (vips_gamma(fred, &jim, NULL))
    ...error;
```

Some operators have many C convenience functions.

# All libvips operators

This table lists all the libvips operators with their C convenience functions
and a short description. It's supposed to be useful for searching. See the
API docs each function links to for more details.

| Operator | Description | C functions |
| -------- | ----------- | ----------- |""")

    gen_function_list()
