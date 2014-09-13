#!/usr/bin/python

import unittest

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

formats = [Vips.BandFormat.UCHAR, 
           Vips.BandFormat.CHAR, 
           Vips.BandFormat.USHORT, 
           Vips.BandFormat.SHORT, 
           Vips.BandFormat.UINT, 
           Vips.BandFormat.INT, 
           Vips.BandFormat.FLOAT, 
           Vips.BandFormat.DOUBLE]
cformats = [Vips.BandFormat.COMPLEX, 
            Vips.BandFormat.DPCOMPLEX] 
all_formats = formats + cformats;

black = Vips.Image.black(100, 100)
red = black.copy()
green = black.copy()
blue = black.copy()
red.draw_circle(100, 50, 50, 40, fill = True)
green.draw_circle(128, 50, 50, 40, fill = True)
blue.draw_circle(140, 50, 50, 40, fill = True)
colour = Vips.Image.bandjoin([red, green, blue])
all_images = [green, colour]

# an expanding zip ... if either of the args is not a list, duplicate it down
# the other
def zip_expand(x, y):
    if isinstance(x, list) and isinstance(y, list):
        return zip(x, y)
    elif isinstance(x, list):
        return [[i, y] for i in x]
    elif isinstance(y, list):
        return [[x, j] for j in y]
    else:
        return [[x, y]]

# run a 2-ary function on two things -- loop over elements pairwise if the 
# things are lists
def run_fn2(fn, x, y):
    if isinstance(x, Vips.Image) or isinstance(y, Vips.Image):
        return fn(x, y)
    elif isinstance(x, list) or isinstance(y, list):
        return [fn(i, j) for i, j in zip_expand(x, y)]
    else:
        return fn(x, y)

class TestArithmetic(unittest.TestCase):
    # test a pait of things which can be lists
    def assertAlmostEqualObjects(self, a, b, msg = ''):
        [self.assertAlmostEqual(x, y, places = 2, msg = msg)
         for x, y in zip_expand(a, b)]

    # run a function on (image, constant), and on (constant, image).
    def run_testconst(self, message, fn, im, c):
        before = im.getpoint(50, 50)
        im1 = fn(c, im)
        im2 = fn(im, c)
        after1 = im1.getpoint(50, 50)
        after2 = im2.getpoint(50, 50)
        c1 = run_fn2(fn, c, before)
        c2 = run_fn2(fn, before, c)
        self.assertAlmostEqualObjects(after1, c1, msg = message)
        self.assertAlmostEqualObjects(after2, c2, msg = message)

    def run_arith_const(self, fn, fmt = all_formats):
        [self.run_testconst(fn.func_name + ' scalar', fn, x.cast(y), 12)
         for x in all_images for y in fmt]
        [self.run_testconst(fn.func_name + ' vector', fn, colour.cast(y), 
                            [12, 13, 14])
         for y in formats]

    # run a function on (image, image)
    def run_testim(self, message, fn, left, right):
        before_left = left.getpoint(50, 50)
        before_right = right.getpoint(50, 50)
        im2 = fn(left, right)
        after = im2.getpoint(50, 50)
        after_c = run_fn2(fn, before_left, before_right)
        self.assertAlmostEqualObjects(after, after_c, msg = message)

    def run_arith(self, fn, fmt = all_formats):
        [self.run_testim(fn.func_name + ' image', fn, x.cast(y), x.cast(z))
         for x in all_images for y in fmt for z in fmt]

    def test_add(self):
        def add(x, y):
            return x + y

        self.run_arith_const(add)
        self.run_arith(add)

    def test_sub(self):
        def sub(x, y):
            return x - y

        self.run_arith_const(sub)
        self.run_arith(sub)

    def test_mul(self):
        def mul(x, y):
            return x * y

        self.run_arith_const(mul)
        self.run_arith(mul)

    def test_div(self):
        def div(x, y):
            return x / y

        # div(const / image) needs (image ** -1), which won't work for complex
        # images ... just test with non-complex
        self.run_arith_const(div, fmt = formats)

        self.run_arith(div)

if __name__ == '__main__':
    unittest.main()

