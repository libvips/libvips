#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

a = Vips.Image.new_from_file(sys.argv[1])

# test operator overloads
b = a + 12
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

