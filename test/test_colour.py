#!/usr/bin/python

import unittest
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

colour_colourspaces = [Vips.Interpretation.XYZ,
                       Vips.Interpretation.LAB,
                       Vips.Interpretation.LCH,
                       Vips.Interpretation.CMC,
                       Vips.Interpretation.LABS,
                       Vips.Interpretation.SCRGB,
                       Vips.Interpretation.SRGB,
                       Vips.Interpretation.RGB16,
                       Vips.Interpretation.YXY]
coded_colourspaces = [Vips.Interpretation.LABQ]
mono_colourspaces = [Vips.Interpretation.GREY16,
                     Vips.Interpretation.B_W]
all_colourspaces = colour_colourspaces + mono_colourspaces + coded_colourspaces

# an expanding zip ... if either of the args is not a list, duplicate it down
# the other
def zip_expand(x, y):
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
        im = Vips.Image.mask_ideal(100, 100, 0.5, reject = True, optical = True)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour.extract_band(1)
        self.all_images = [self.mono, self.colour]

    def test_colourspace(self):
        # mid-grey in Lab ... put 42 in the extra band, it should be copied
        # unmodified
        test = Vips.Image.black(100, 100) + [50, 0, 0, 42]
        test = test.copy(interpretation = Vips.Interpretation.LAB)

        # a long series should come in a circle
        im = test
        for col in colour_colourspaces + [Vips.Interpretation.LAB]:
            im = im.colourspace(col)
            self.assertEqual(im.interpretation, col)
            pixel = im.getpoint(10, 10)
            self.assertAlmostEqual(pixel[3], 42, places = 2)

        before = test.getpoint(10, 10)
        after = im.getpoint(10, 10)
        self.assertAlmostEqualObjects(before, after, places = 1)

        # go between every pair of colour spaces
        for start in colour_colourspaces:
            for end in colour_colourspaces:
                im = test.colourspace(start)
                im2 = im.colourspace(end)
                im3 = im2.colourspace(Vips.Interpretation.LAB)

                before = test.getpoint(10, 10)
                after = im3.getpoint(10, 10)
                self.assertAlmostEqualObjects(before, after, places = 1)

        # test Lab->XYZ on mid-grey
        # checked against http://www.brucelindbloom.com
        im = test.colourspace(Vips.Interpretation.XYZ)
        after = im.getpoint(10, 10)
        self.assertAlmostEqualObjects(after, [17.5064, 18.4187, 20.0547, 42])

        # grey->colour->grey should be equal
        for mono_fmt in mono_colourspaces:
            test_grey = test.colourspace(mono_fmt)
            im = test_grey
            for col in colour_colourspaces + [mono_fmt]:
                im = im.colourspace(col)
                self.assertEqual(im.interpretation, col)
            [before, alpha_before] = test_grey.getpoint(10, 10)
            [after, alpha_after] = im.getpoint(10, 10)
            self.assertLess(abs(alpha_after - alpha_before), 1)
            if mono_fmt == Vips.Interpretation.GREY16:
                # GREY16 can wind up rather different due to rounding
                self.assertLess(abs(after - before), 30)
            else:
                # but 8-bit we should hit exactly
                self.assertLess(abs(after - before), 1)

    # test results from Bruce Lindbloom's calculator:
    # http://www.brucelindbloom.com

    def test_dE00(self):
        # put 42 in the extra band, it should be copied unmodified
        reference = Vips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation = Vips.Interpretation.LAB)
        sample = Vips.Image.black(100, 100) + [40, -20, 10]
        sample = sample.copy(interpretation = Vips.Interpretation.LAB)

        difference = reference.dE00(sample)
        result, alpha = difference.getpoint(10, 10)
        self.assertAlmostEqual(result, 30.238, places = 3)
        self.assertAlmostEqual(alpha, 42.0, places = 3)

    def test_dE76(self):
        # put 42 in the extra band, it should be copied unmodified
        reference = Vips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation = Vips.Interpretation.LAB)
        sample = Vips.Image.black(100, 100) + [40, -20, 10]
        sample = sample.copy(interpretation = Vips.Interpretation.LAB)

        difference = reference.dE76(sample)
        result, alpha = difference.getpoint(10, 10)
        self.assertAlmostEqual(result, 33.166, places = 3)
        self.assertAlmostEqual(alpha, 42.0, places = 3)

    # the vips CMC calculation is based on distance in a colorspace derived from
    # the CMC formula, so it won't match exactly ... see vips_LCh2CMC() for
    # details
    def test_dECMC(self):
        reference = Vips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation = Vips.Interpretation.LAB)
        sample = Vips.Image.black(100, 100) + [55, 11, 23]
        sample = sample.copy(interpretation = Vips.Interpretation.LAB)

        difference = reference.dECMC(sample)
        result, alpha = difference.getpoint(10, 10)
        self.assertLess(abs(result - 4.97), 0.5)
        self.assertAlmostEqual(alpha, 42.0, places = 3)

    def test_icc(self):
        test = Vips.Image.new_from_file("images/IMG_4618.jpg")

        im = test.icc_import().icc_export()
        self.assertLess(im.dE76(test).max(), 6)

        im = test.icc_import()
        im2 = im.icc_export(depth = 16)
        self.assertEqual(im2.format, Vips.BandFormat.USHORT)
        im3 = im2.icc_import()
        self.assertLess((im - im3).abs().max(), 3)

        im = test.icc_import(intent = Vips.Intent.ABSOLUTE)
        im2 = im.icc_export(intent = Vips.Intent.ABSOLUTE)
        self.assertLess(im2.dE76(test).max(), 6)

        im = test.icc_import()
        im2 = im.icc_export(output_profile = "images/sRGB.icm")
        im3 = im.colourspace(Vips.Interpretation.SRGB)
        self.assertLess(im2.dE76(im3).max(), 6)

        before_profile = test.get_value("icc-profile-data")
        im = test.icc_transform("images/sRGB.icm")
        after_profile = im.get_value("icc-profile-data")
        im2 = test.icc_import()
        im3 = im2.colourspace(Vips.Interpretation.SRGB)
        self.assertLess(im.dE76(im3).max(), 6)
        self.assertNotEqual(len(before_profile), len(after_profile))

        im = test.icc_import(input_profile = "images/sRGB.icm")
        im2 = test.icc_import()
        self.assertLess(6, im.dE76(im2).max())

        im = test.icc_import(pcs = Vips.PCS.XYZ)
        self.assertEqual(im.interpretation, Vips.Interpretation.XYZ)
        im = test.icc_import()
        self.assertEqual(im.interpretation, Vips.Interpretation.LAB)

if __name__ == '__main__':
    unittest.main()
