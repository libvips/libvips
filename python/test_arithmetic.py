#!/usr/bin/python

import unittest

import logging
logging.basicConfig(level = logging.DEBUG)

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

im = Vips.Image.mask_ideal(100, 100, 0.5)
colour = im * [100, 128, 140] + [20, 30, 40]
mono = colour.extract_band(1)
all_images = [mono, colour]

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

# run a 1-ary function on a thing -- loop over elements if the 
# thing is a list
def run_fn(fn, x):
    if isinstance(x, Vips.Image) :
        return fn(x)
    elif isinstance(x, list):
        return [fn(i) for i in x]
    else:
        return fn(x)

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
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, msg = ''):
        [self.assertAlmostEqual(x, y, places = 2, msg = msg)
         for x, y in zip_expand(a, b)]

    # run a function on an image and on a single pixel, the results 
    # should match 
    def run_cmp(self, message, im, x, y, fn):
        a = im.getpoint(x, y)
        v1 = fn(a)
        im2 = fn(im)
        v2 = im2.getpoint(x, y)
        #print 'self.assertAlmostEqualObjects: %s = %s' % (v1, v2) 
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on (image, constant), and on (constant, image).
    # 50,50 and 10,10 should have different values on the test image
    def run_testconst(self, message, fn, im, c):
        self.run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, x, c))
        self.run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, c, x))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, x, c))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, c, x))

    def run_arith_const(self, fn, fmt = all_formats):
        [self.run_testconst(fn.func_name + ' scalar', fn, x.cast(y), 12)
         for x in all_images for y in fmt]
        [self.run_testconst(fn.func_name + ' vector', fn, colour.cast(y), 
                            [12, 13, 14])
         for y in formats]

    # run a function on a pair of images and on a pair of pixels, the results 
    # should match 
    def run_cmp2(self, message, left, right, x, y, fn):
        a = left.getpoint(x, y)
        b = right.getpoint(x, y)
        v1 = fn(a, b)
        after = fn(left, right)
        v2 = after.getpoint(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on a pair of images
    # 50,50 and 10,10 should have different values on the test image
    def run_test2(self, message, left, right, fn):
        self.run_cmp2(message, left, right, 50, 50, 
                      lambda x, y: run_fn2(fn, x, y))
        self.run_cmp2(message, left, right, 10, 10, 
                      lambda x, y: run_fn2(fn, x, y))

    def run_arith(self, fn, fmt = all_formats):
        [self.run_test2(fn.func_name + ' image', x.cast(y), x.cast(z), fn)
         for x in all_images for y in fmt for z in fmt]

    def test_add(self):
        def add(x, y):
            return x + y

        #self.run_arith_const(add)
        #self.run_arith(add)

    def test_sub(self):
        def sub(x, y):
            return x - y

        #self.run_arith_const(sub)
        #self.run_arith(sub)

    def test_mul(self):
        def mul(x, y):
            return x * y

        #self.run_arith_const(mul)
        #self.run_arith(mul)

    def test_div(self):
        def div(x, y):
            return x / y

        # div(const / image) needs (image ** -1), which won't work for complex
        # images ... just test with non-complex
        #self.run_arith_const(div, fmt = formats)
        #self.run_arith(div)

    # run a function on an image, 
    # 50,50 and 10,10 should have different values on the test image
    def run_testunary(self, message, im, fn):
        self.run_cmp(message, im, 50, 50, lambda x: run_fn(fn, x))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn(fn, x))

    def run_unary(self, fn, images = all_images, fmt = all_formats):
        [self.run_testunary(fn.func_name + ' image', x.cast(y), fn)
         for x in images for y in fmt]

    def test_abs(self):
        def my_abs(x):
            return abs(x)

        #im = -mono;
        #self.run_unary(my_abs, [im])

if __name__ == '__main__':
    unittest.main()
