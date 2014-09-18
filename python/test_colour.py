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

colour_colourspaces = [Vips.Interpretation.XYZ,
                       Vips.Interpretation.LAB,
                       Vips.Interpretation.LABQ,
                       Vips.Interpretation.LCH,
                       Vips.Interpretation.CMC,
                       Vips.Interpretation.LABS,
                       Vips.Interpretation.SCRGB,
                       Vips.Interpretation.SRGB,
                       Vips.Interpretation.RGB16,
                       Vips.Interpretation.YXY]
mono_colourspaces = [Vips.Interpretation.GREY16,
                     Vips.Interpretation.B_W]
all_colourspaces = colour_colourspaces + mono_colourspaces

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

class TestColour(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        #print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    # run a function on an image and on a single pixel, the results 
    # should match 
    def run_cmp(self, message, im, x, y, fn):
        a = im.getpoint(x, y)
        v1 = fn(a)
        im2 = fn(im)
        v2 = im2.getpoint(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

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

    def setUp(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5, optical = True)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour.extract_band(1)
        self.all_images = [self.mono, self.colour]

    def test_colourspace(self):
        # mid-grey in Lab
        test = Vips.Image.black(100, 100) + [50, 0, 0]
        test = test.copy(interpretation = Vips.Interpretation.LAB)

        im = test
        for col in colour_colourspaces + [Vips.Interpretation.LAB]:
            im = im.colourspace(col)
            self.assertEqual(im.interpretation, col)

        before = test.getpoint(10, 10)
        after = im.getpoint(10, 10)
        self.assertAlmostEqualObjects(before, after, places = 1)

        test = Vips.Image.black(100, 100) + [50, 0, 0]
        test = test.copy(interpretation = Vips.Interpretation.LAB)
        im = im.colourspace(Vips.Interpretation.XYZ)
        after = im.getpoint(10, 10)

        print 'after =', after
        self.assertAlmostEqualObjects(after, [17.5064, 18.4187, 20.0547])
    



if __name__ == '__main__':
    unittest.main()
