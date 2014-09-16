#!/usr/bin/python

import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

unsigned_formats = [Vips.BandFormat.UCHAR, 
                    Vips.BandFormat.USHORT, 
                    Vips.BandFormat.UINT] 
signed_formats = [Vips.BandFormat.CHAR, 
                  Vips.BandFormat.SHORT, 
                  Vips.BandFormat.INT] 
float_formats = [Vips.BandFormat.FLOAT, 
                 Vips.BandFormat.DOUBLE]
complex_formats = [Vips.BandFormat.COMPLEX, 
                   Vips.BandFormat.DPCOMPLEX] 
int_formats = unsigned_formats + signed_formats
noncomplex_formats = int_formats + float_formats
all_formats = int_formats + float_formats + complex_formats

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
    if isinstance(x, list):
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
        for x, y in zip_expand(a, b):
            #print 'assertAlmostEqual %s = %s' % (x, y)
            self.assertAlmostEqual(x, y, places = 4, msg = msg)

    # run a function on an image and on a single pixel, the results 
    # should match 
    def run_cmp(self, message, im, x, y, fn):
        a = im.getpoint(x, y)
        v1 = fn(a)
        im2 = fn(im)
        v2 = im2.getpoint(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on (image, constant), and on (constant, image).
    # 50,50 and 10,10 should have different values on the test image
    def run_testconst(self, message, fn, im, c):
        self.run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, x, c))
        self.run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, c, x))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, x, c))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, c, x))

    def run_arith_const(self, fn, fmt = all_formats):
        [self.run_testconst(fn.func_name + ' scalar', fn, x.cast(y), 2)
         for x in self.all_images for y in fmt]
        [self.run_testconst(fn.func_name + ' vector', fn, self.colour.cast(y), 
                            [1, 2, 3])
         for y in fmt]

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
         for x in self.all_images for y in fmt for z in fmt]

    def setUp(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour.extract_band(1)
        self.all_images = [self.mono, self.colour]

    # test all operator overloads we define

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

        # (const / image) needs (image ** -1), which won't work for complex
        self.run_arith_const(div, fmt = noncomplex_formats)
        self.run_arith(div)

    def test_floordiv(self):
        def my_floordiv(x, y):
            return x // y

        # (const // image) needs (image ** -1), which won't work for complex
        self.run_arith_const(my_floordiv, fmt = noncomplex_formats)
        self.run_arith(my_floordiv, fmt = noncomplex_formats)

    def test_pow(self):
        def my_pow(x, y):
            return x ** y

        # (image ** x) won't work for complex images ... just test non-complex
        self.run_arith_const(my_pow, fmt = noncomplex_formats)
        self.run_arith(my_pow, fmt = noncomplex_formats)

    def test_and(self):
        def my_and(x, y):
            # python doesn't allow bools on float 
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x & y

        self.run_arith_const(my_and, fmt = noncomplex_formats)
        self.run_arith(my_and, fmt = noncomplex_formats)

    def test_or(self):
        def my_or(x, y):
            # python doesn't allow bools on float 
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x | y

        self.run_arith_const(my_or, fmt = noncomplex_formats)
        self.run_arith(my_or, fmt = noncomplex_formats)

    def test_xor(self):
        def my_xor(x, y):
            # python doesn't allow bools on float 
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x ^ y

        self.run_arith_const(my_xor, fmt = noncomplex_formats)
        self.run_arith(my_xor, fmt = noncomplex_formats)

    # run a function on an image, 
    # 50,50 and 10,10 should have different values on the test image
    def run_testunary(self, message, im, fn):
        self.run_cmp(message, im, 50, 50, lambda x: run_fn(fn, x))
        self.run_cmp(message, im, 10, 10, lambda x: run_fn(fn, x))

    def run_unary(self, images, fn, fmt = all_formats):
        [self.run_testunary(fn.func_name + ' image', x.cast(y), fn)
         for x in images for y in fmt]

    def test_abs(self):
        def my_abs(x):
            return abs(x)

        im = -self.colour
        self.run_unary([im], my_abs)

    def test_lshift(self):
        def my_lshift(x):
            # python doesn't allow float << int
            if isinstance(x, float):
                x = int(x)
            return x << 2

        # we don't support constant << image, treat as a unary
        self.run_unary(self.all_images, my_lshift, fmt = noncomplex_formats)

    def test_rshift(self):
        def my_rshift(x):
            # python doesn't allow float >> int
            if isinstance(x, float):
                x = int(x)
            return x >> 2

        # we don't support constant >> image, treat as a unary
        self.run_unary(self.all_images, my_rshift, fmt = noncomplex_formats)

    def test_mod(self):
        def my_mod(x):
            return x % 2

        # we don't support constant % image, treat as a unary
        self.run_unary(self.all_images, my_mod, fmt = noncomplex_formats)

    def test_pos(self):
        def my_pos(x):
            return +x

        self.run_unary(self.all_images, my_pos)

    def test_neg(self):
        def my_neg(x):
            return -x

        self.run_unary(self.all_images, my_neg)

    def test_invert(self):
        def my_invert(x):
            if isinstance(x, float):
                x = int(x)
            return ~x & 0xff

        # ~image is trimmed to image max so it's hard to test for all formats
        # just test uchar
        self.run_unary(self.all_images, my_invert, 
                       fmt = [Vips.BandFormat.UCHAR])

    # test the rest of VipsArithmetic

    def test_avg(self):
        im = Vips.Image.black(50, 100)
        test = im.insert(im + 100, 50, 0, expand = True)

        for fmt in all_formats:
            self.assertAlmostEqual(test.cast(fmt).avg(), 50)

    def test_deviate(self):
        im = Vips.Image.black(50, 100)
        test = im.insert(im + 100, 50, 0, expand = True)

        for fmt in noncomplex_formats:
            self.assertAlmostEqual(test.cast(fmt).deviate(), 50, places = 2)

    def test_polar(self):
        im = Vips.Image.black(100, 100) + 100
        im = im.complexform(im)

        im = im.polar()

        self.assertAlmostEqual(im.real().avg(), 100 * 2 ** 0.5)
        self.assertAlmostEqual(im.imag().avg(), 45)

    def test_rect(self):
        im = Vips.Image.black(100, 100)
        im = (im + 100 * 2 ** 0.5).complexform(im + 45)

        im = im.rect()

        self.assertAlmostEqual(im.real().avg(), 100)
        self.assertAlmostEqual(im.imag().avg(), 100)

    def test_conjugate(self):
        im = Vips.Image.black(100, 100) + 100
        im = im.complexform(im)

        im = im.conj()

        self.assertAlmostEqual(im.real().avg(), 100)
        self.assertAlmostEqual(im.imag().avg(), -100)

    def test_histfind(self):
        im = Vips.Image.black(50, 100)
        test = im.insert(im + 10, 50, 0, expand = True)

        for fmt in all_formats:
            hist = test.cast(fmt).hist_find()
            self.assertAlmostEqualObjects(hist.getpoint(0,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(10,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(5,0), [0])

        test = test * [1, 2, 3]

        for fmt in all_formats:
            hist = test.cast(fmt).hist_find(band = 0)
            self.assertAlmostEqualObjects(hist.getpoint(0,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(10,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(5,0), [0])

            hist = test.cast(fmt).hist_find(band = 1)
            self.assertAlmostEqualObjects(hist.getpoint(0,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(20,0), [5000])
            self.assertAlmostEqualObjects(hist.getpoint(5,0), [0])

    def test_histfind_indexed(self):
        im = Vips.Image.black(50, 100)
        test = im.insert(im + 10, 50, 0, expand = True)
        index = test / 10

        for x in noncomplex_formats:
            for y in [Vips.BandFormat.UCHAR, Vips.BandFormat.USHORT]:
                a = test.cast(x)
                b = index.cast(y)
                hist = a.hist_find_indexed(b)

                self.assertAlmostEqualObjects(hist.getpoint(0,0), [0])
                self.assertAlmostEqualObjects(hist.getpoint(1,0), [50000])

    def test_histfind_ndim(self):
        im = Vips.Image.black(100, 100) + [1, 2, 3]

        for fmt in noncomplex_formats:
            hist = im.cast(fmt).hist_find_ndim()

            self.assertAlmostEqualObjects(hist.getpoint(0,0)[0], 10000)
            self.assertAlmostEqualObjects(hist.getpoint(5,5)[5], 0)

            hist = im.cast(fmt).hist_find_ndim(bins = 1)

            self.assertAlmostEqualObjects(hist.getpoint(0,0)[0], 10000)
            self.assertEqual(hist.width, 1)
            self.assertEqual(hist.height, 1)
            self.assertEqual(hist.bands, 1)

    def test_hough_circle(self):
        test = Vips.Image.black(100, 100).draw_circle(100, 50, 50, 40)

        for fmt in all_formats:
            im = test.cast(fmt)
            hough = im.hough_circle(min_radius = 35, max_radius = 45)

            v, x, y = hough.maxpos()
            vec = hough.getpoint(x, y)
            r = vec.index(v) + 35

            self.assertAlmostEqual(x, 50)
            self.assertAlmostEqual(y, 50)
            self.assertAlmostEqual(r, 40)

    def test_hough_line(self):
        test = Vips.Image.black(100, 100).draw_line(100, 10, 90, 90, 10)

        for fmt in all_formats:
            im = test.cast(fmt)
            hough = im.hough_line()
            
            v, x, y = hough.maxpos()

            angle = 360.0 * x / hough.width 
            distance = test.height * y / hough.height

            self.assertAlmostEqual(angle, 45)
            self.assertAlmostEqual(distance, 70)

    def test_sin(self):
        def my_sin(x):
            if isinstance(x, Vips.Image):
                return x.sin()
            else:
                return math.sin(math.radians(x))

        self.run_unary(self.all_images, my_sin, fmt = noncomplex_formats)

    def test_cos(self):
        def my_cos(x):
            if isinstance(x, Vips.Image):
                return x.cos()
            else:
                return math.cos(math.radians(x))

        self.run_unary(self.all_images, my_cos, fmt = noncomplex_formats)

    def test_tan(self):
        def my_tan(x):
            if isinstance(x, Vips.Image):
                return x.tan()
            else:
                return math.tan(math.radians(x))

        self.run_unary(self.all_images, my_tan, fmt = noncomplex_formats)

    def test_asin(self):
        def my_asin(x):
            if isinstance(x, Vips.Image):
                return x.asin()
            else:
                return math.degrees(math.asin(x))

        im = (Vips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_asin, fmt = noncomplex_formats)

    def test_acos(self):
        def my_acos(x):
            if isinstance(x, Vips.Image):
                return x.acos()
            else:
                return math.degrees(math.acos(x))

        im = (Vips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_acos, fmt = noncomplex_formats)

    def test_atan(self):
        def my_atan(x):
            if isinstance(x, Vips.Image):
                return x.atan()
            else:
                return math.degrees(math.atan(x))

        im = (Vips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_atan, fmt = noncomplex_formats)

    def test_log(self):
        def my_log(x):
            if isinstance(x, Vips.Image):
                return x.log()
            else:
                return math.log(x)

        self.run_unary(self.all_images, my_log, fmt = noncomplex_formats)

    def test_log10(self):
        def my_log10(x):
            if isinstance(x, Vips.Image):
                return x.log10()
            else:
                return math.log10(x)

        self.run_unary(self.all_images, my_log10, fmt = noncomplex_formats)

    def test_exp(self):
        def my_exp(x):
            if isinstance(x, Vips.Image):
                return x.exp()
            else:
                return math.exp(x)

        self.run_unary(self.all_images, my_exp, fmt = noncomplex_formats)

    def test_exp10(self):
        def my_exp10(x):
            if isinstance(x, Vips.Image):
                return x.exp10()
            else:
                return math.pow(10, x)

        self.run_unary(self.all_images, my_exp10, fmt = noncomplex_formats)

if __name__ == '__main__':
    unittest.main()
