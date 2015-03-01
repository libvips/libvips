#!/usr/bin/python3

from __future__ import division
from numbers import Number
from functools import reduce

import unittest
import operator
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

Vips.leak_set(True)

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

# an expanding zip ... if either of the args is a scalar or a one-element list,
# duplicate it down the other side 
def zip_expand(x, y):
    # handle singleton list case
    if isinstance(x, list) and len(x) == 1:
        x = x[0]
    if isinstance(y, list) and len(y) == 1:
        y = y[0]

    if isinstance(x, list) and isinstance(y, list):
        return list(zip(x, y))
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

# point convolution
def conv(image, mask, x_position, y_position):
    s = 0.0
    for x in range(0, mask.width):
        for y in range(0, mask.height):
            m = mask(x, y)
            i = image(x + x_position, y + y_position)
            p = run_fn2(operator.mul, m, i)
            s = run_fn2(operator.add, s, p)

    return run_fn2(operator.truediv, s, mask.get_scale())

def compass(image, mask, x_position, y_position, n_rot, fn):
    acc = []
    for i in range(0, n_rot):
        result = conv(image, mask, x_position, y_position)
        result = run_fn(abs, result)
        acc.append(result)
        mask = mask.rot45()

    return reduce(lambda a, b: run_fn2(fn, a, b), acc)

class TestConvolution(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        #print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def setUp(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5, reject = True, optical = True)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour.extract_band(1)
        self.all_images = [self.mono, self.colour]
        self.sharp = Vips.Image.new_from_array([[-1, -1,  -1], 
                                                [-1,  16, -1], 
                                                [-1, -1,  -1]], scale = 8)
        self.blur = Vips.Image.new_from_array([[1, 1, 1], 
                                               [1, 1, 1], 
                                               [1, 1, 1]], scale = 9)
        self.line = Vips.Image.new_from_array([[ 1,  1,  1], 
                                               [-2, -2, -2], 
                                               [ 1,  1,  1]])
        self.sobel = Vips.Image.new_from_array([[ 1,  2,  1], 
                                                [ 0,  0,  0], 
                                                [-1, -2, -1]])
        self.all_masks = [self.sharp, self.blur, self.line, self.sobel]

    def test_conv(self):
        for im in self.all_images:
            for msk in self.all_masks:
                for prec in [Vips.Precision.INTEGER, Vips.Precision.FLOAT]:
                    convolved = im.conv(msk, precision = prec)

                    result = convolved(25, 50)
                    true = conv(im, msk, 24, 49)
                    self.assertAlmostEqualObjects(result, true)

                    result = convolved(50, 50)
                    true = conv(im, msk, 49, 49)
                    self.assertAlmostEqualObjects(result, true)

    def test_compass(self):
        for im in self.all_images:
            for msk in self.all_masks:
                for prec in [Vips.Precision.INTEGER, Vips.Precision.FLOAT]:
                    for times in range(1, 4):
                        convolved = im.compass(msk, 
                                               times = times, 
                                               angle = Vips.Angle45.D45,
                                               combine = Vips.Combine.MAX,
                                               precision = prec)

                        result = convolved(25, 50)
                        true = compass(im, msk, 24, 49, times, max)
                        self.assertAlmostEqualObjects(result, true)

        for im in self.all_images:
            for msk in self.all_masks:
                for prec in [Vips.Precision.INTEGER, Vips.Precision.FLOAT]:
                    for times in range(1, 4):
                        convolved = im.compass(msk, 
                                               times = times, 
                                               angle = Vips.Angle45.D45,
                                               combine = Vips.Combine.SUM,
                                               precision = prec)

                        result = convolved(25, 50)
                        true = compass(im, msk, 24, 49, times, operator.add)
                        self.assertAlmostEqualObjects(result, true)

    def test_convsep(self):
        for im in self.all_images:
            for prec in [Vips.Precision.INTEGER, Vips.Precision.FLOAT]:
                gmask = Vips.Image.gaussmat(2, 0.1, 
                                            precision = prec)
                gmask_sep = Vips.Image.gaussmat(2, 0.1, 
                                                separable = True,
                                                precision = prec)

                self.assertEqual(gmask.width, gmask.height)
                self.assertEqual(gmask_sep.width, gmask.width)
                self.assertEqual(gmask_sep.height, 1)

                a = im.conv(gmask, precision = prec)
                b = im.convsep(gmask_sep, precision = prec)

                a_point = a(25, 50)
                b_point = b(25, 50)

                self.assertAlmostEqualObjects(a_point, b_point, places = 1)

    def test_fastcor(self):
        for im in self.all_images:
            for fmt in noncomplex_formats:
                small = im.crop(20, 45, 10, 10).cast(fmt)
                cor = im.fastcor(small)
                v, x, y = cor.minpos()

                self.assertEqual(v, 0)
                self.assertEqual(x, 25)
                self.assertEqual(y, 50)

    def test_spcor(self):
        for im in self.all_images:
            for fmt in noncomplex_formats:
                small = im.crop(20, 45, 10, 10).cast(fmt)
                cor = im.spcor(small)
                v, x, y = cor.maxpos()

                self.assertEqual(v, 1.0)
                self.assertEqual(x, 25)
                self.assertEqual(y, 50)

    def test_gaussblur(self):
        for im in self.all_images:
            for prec in [Vips.Precision.INTEGER, Vips.Precision.FLOAT]:
                for i in range(5, 10):
                    sigma = i / 5.0
                    gmask = Vips.Image.gaussmat(sigma, 0.2, 
                                                precision = prec)

                    a = im.conv(gmask, precision = prec)
                    b = im.gaussblur(sigma, min_ampl = 0.2, precision = prec)

                    a_point = a(25, 50)
                    b_point = b(25, 50)

                    self.assertAlmostEqualObjects(a_point, b_point, places = 1)

    def test_sharpen(self):
        for im in self.all_images:
            for fmt in noncomplex_formats:
                for radius in range(1, 7):
                    im = im.cast(fmt)
                    if im.bands == 3:
                        im = im.copy(interpretation = Vips.Interpretation.SRGB)
                    sharp = im.sharpen(radius = radius)

                    # hard to test much more than this
                    self.assertEqual(im.width, sharp.width)
                    self.assertEqual(im.height, sharp.height)

if __name__ == '__main__':
    unittest.main()
