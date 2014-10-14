#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

a = Vips.Image.new_from_file(sys.argv[1])

def should_equal(test, a, b):
    if abs(a - b) > 0.01:
        print '%s: seen %g and %g' % (test, a, b)
        sys.exit(1)

def bandsplit(a):
    return [a.extract_band(i) for i in range(0, a.bands)]

# test operator overloads

# addition
b = a + 12
should_equal('add constant', a.avg() + 12, b.avg())

b = a + [12, 0, 0]
x = map (lambda x: x.avg()) bandsplit(a)
y = map (lambda x: x.avg()) bandsplit(b)
x[0] += 12
should_equal('add multiband constant', sum(x), sum(y))


b = a + [12, 0, 0]
b = a + b
b = 12 + a
b = [12, 0, 0] + a

b = a - 12
b = a - [12, 0, 0]
b = a - b
b = 12 - a
b = [12, 0, 0] - a

b = a * 12
b = a * [12, 1, 1]
b = a * b
b = 12 * a
b = [12, 1, 1] * a

b = a / 12
b = a / [12, 1, 1]
b = 12 / a
b = [12, 1, 1] / a
b = a / b

b = a // 12
b = a // [12, 1, 1]
b = 12 // a
b = [12, 1, 1] // a
b = a // b

b = a % 12
b = a % [12, 1, 1]
b = a % b

b = a ** 12
b = a ** [12, 1, 1]
b = 12 ** a
b = [12, 1, 1] ** a
b = a ** b

b = a << 12
b = a << [12, 1, 1]
b = a << b

b = a >> 12
b = a >> [12, 1, 1]
b = a >> b

b = a & 12
b = a & [12, 1, 1]
b = 12 & a
b = [12, 1, 1] & a
b = a & b

b = a | 12
b = a | [12, 1, 1]
b = 12 | a
b = [12, 1, 1] | a
b = a | b

b = a ^ 12
b = a ^ [12, 1, 1]
b = 12 ^ a
b = [12, 1, 1] ^ a
b = a ^ b

b = -a
b = +a
b = abs(a)
b = ~a

