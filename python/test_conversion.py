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

class TestConversion(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        #print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    # run a function on an image and on a single pixel, the results 
    # should match 
    def run_cmp_unary(self, message, im, x, y, fn):
        a = im.getpoint(x, y)
        v1 = fn(a)
        im2 = fn(im)
        v2 = im2.getpoint(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on a pair of images and on a pair of pixels, the results 
    # should match 
    def run_cmp_binary(self, message, left, right, x, y, fn):
        a = left.getpoint(x, y)
        b = right.getpoint(x, y)
        v1 = fn(a, b)
        after = fn(left, right)
        v2 = after.getpoint(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on a pair of images
    # 50,50 and 10,10 should have different values on the test image
    def run_testbinary(self, message, left, right, fn):
        self.run_cmp_binary(message, left, right, 50, 50, fn)
        self.run_cmp_binary(message, left, right, 10, 10, fn)

    # run a function on an image, 
    # 50,50 and 10,10 should have different values on the test image
    def run_testunary(self, message, im, fn):
        self.run_cmp_unary(message, im, 50, 50, fn)
        self.run_cmp_unary(message, im, 10, 10, fn)

    def run_unary(self, images, fn, fmt = all_formats):
        [self.run_testunary(fn.func_name + (' %s' % y), x.cast(y), fn)
         for x in images for y in fmt]

    def run_binary(self, images, fn, fmt = all_formats):
        [self.run_testbinary(fn.func_name + (' %s %s' % (y, z)), 
                             x.cast(y), x.cast(z), fn)
         for x in images for y in fmt for z in fmt]

    def setUp(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5, reject = True, optical = True)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour.extract_band(1)
        self.all_images = [self.mono, self.colour]

    def test_band_and(self):
        def band_and(x):
            if isinstance(x, Vips.Image):
                return x.bandbool(Vips.OperationBoolean.AND)
            else:
                return [reduce(lambda a, b: int(a) & int(b), x)]

        self.run_unary([self.colour], band_and, fmt = int_formats)

    def test_band_or(self):
        def band_or(x):
            if isinstance(x, Vips.Image):
                return x.bandbool(Vips.OperationBoolean.OR)
            else:
                return [reduce(lambda a, b: int(a) | int(b), x)]

        self.run_unary([self.colour], band_or, fmt = int_formats)

    def test_band_eor(self):
        def band_eor(x):
            if isinstance(x, Vips.Image):
                return x.bandbool(Vips.OperationBoolean.EOR)
            else:
                return [reduce(lambda a, b: int(a) ^ int(b), x)]

        self.run_unary([self.colour], band_eor, fmt = int_formats)

    def test_bandjoin(self):
        def bandjoin(x, y):
            if isinstance(x, Vips.Image) and isinstance(y, Vips.Image):
                return x.bandjoin2(y)
            else:
                return x + y

        self.run_binary(self.all_images, bandjoin)

    def test_bandmean(self):
        def bandmean(x):
            if isinstance(x, Vips.Image):
                return x.bandmean()
            else:
                return [sum(x) / len(x)]

        self.run_unary([self.colour], bandmean, fmt = noncomplex_formats)

    def test_bandrank(self):
        def median(x, y):
            joined = [[a, b] for a, b in zip(x, y)]
            # .sort() isn't a function, so we have to run this as a separate
            # pass
            [x.sort() for x in joined]
            return [x[len(x) / 2] for x in joined]

        def bandrank(x, y):
            if isinstance(x, Vips.Image) and isinstance(y, Vips.Image):
                return Vips.Image.bandrank([x, y])
            else:
                return median(x, y)

        self.run_binary(self.all_images, bandrank, fmt = noncomplex_formats)

    def test_cache(self):
        def cache(x):
            if isinstance(x, Vips.Image):
                return x.cache()
            else:
                return x

        self.run_unary(self.all_images, cache)

    def test_copy(self):
        x = self.colour.copy(interpretation = Vips.Interpretation.LAB)
        self.assertEqual(x.interpretation, Vips.Interpretation.LAB)
        x = self.colour.copy(xres = 42)
        self.assertEqual(x.xres, 42)
        x = self.colour.copy(yres = 42)
        self.assertEqual(x.yres, 42)
        x = self.colour.copy(xoffset = 42)
        self.assertEqual(x.xoffset, 42)
        x = self.colour.copy(yoffset = 42)
        self.assertEqual(x.yoffset, 42)
        x = self.colour.copy(bands = 1)
        self.assertEqual(x.bands, 1)
        x = self.colour.copy(format = Vips.BandFormat.USHORT, bands = 1)
        self.assertEqual(x.format, Vips.BandFormat.USHORT)
        x = self.colour.copy(coding = Vips.Coding.NONE)
        self.assertEqual(x.coding, Vips.Coding.NONE)
        x = self.colour.copy(width = 42)
        self.assertEqual(x.width, 42)
        x = self.colour.copy(height = 42)
        self.assertEqual(x.height, 42)

    def test_embed(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40)
            pixel = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])
            pixel = im.getpoint(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])
            pixel = im.getpoint(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.COPY)
            pixel = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])
            pixel = im.getpoint(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.BACKGROUND,
                            background = [7, 8, 9])
            pixel = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(pixel, [7, 8, 9])
            pixel = im.getpoint(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [7, 8, 9])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.WHITE)
            pixel = im.getpoint(10, 10)
            # uses 255 in all bytes of ints, 255.0 for float
            pixel = [int(x) & 0xff for x in pixel]
            self.assertAlmostEqualObjects(pixel, [255, 255, 255])
            pixel = im.getpoint(im.width - 10, im.height - 10)
            pixel = [int(x) & 0xff for x in pixel]
            self.assertAlmostEqualObjects(pixel, [255, 255, 255])

    def test_extract(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test.getpoint(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.extract_area(25, 25, 10, 10)

            pixel = sub.getpoint(5, 5)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.extract_band(1, n = 2)

            pixel = sub.getpoint(30, 30)
            self.assertAlmostEqualObjects(pixel, [3, 4])

    def test_crop(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test.getpoint(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.crop(25, 25, 10, 10)

            pixel = sub.getpoint(5, 5)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

    def test_falsecolour(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.falsecolour()

            self.assertEqual(im.width, test.width)
            self.assertEqual(im.height, test.height)
            self.assertEqual(im.bands, 3)

            pixel = im.getpoint(30, 30)
            self.assertAlmostEqualObjects(pixel, [20, 0, 41])

    def test_flatten(self):
        max_value = {Vips.BandFormat.UCHAR: 0xff,
                     Vips.BandFormat.USHORT: 0xffff,
                     Vips.BandFormat.UINT: 0xffffffff, 
                     Vips.BandFormat.CHAR: 0x7f,
                     Vips.BandFormat.SHORT: 0x7fff, 
                     Vips.BandFormat.INT: 0x7fffffff,
                     Vips.BandFormat.FLOAT: 1.0,
                     Vips.BandFormat.DOUBLE: 1.0,
                     Vips.BandFormat.COMPLEX: 1.0,
                     Vips.BandFormat.DPCOMPLEX: 1.0}
        black = self.mono * 0.0

        for fmt in all_formats:
            print fmt
            test = self.colour.bandjoin2(black + max_value[fmt] / 2.0).cast(fmt)
            pixel = test.getpoint(30, 30)
            print 'before', pixel

            im = test.flatten()

            self.assertEqual(im.bands, 3)
            pixel = im.getpoint(30, 30)
            print 'after', pixel
            self.assertAlmostEqualObjects(pixel, [0, 1, 1])

            im = test.flatten(background = [100, 100, 100])

            self.assertEqual(im.bands, 3)
            pixel = im.getpoint(30, 30)
            print pixel
            self.assertAlmostEqualObjects(pixel, [50, 51, 51])



if __name__ == '__main__':
    unittest.main()
