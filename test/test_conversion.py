#!/usr/bin/python

from __future__ import division
import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 
from functools import reduce

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

sizeof_format = {Vips.BandFormat.UCHAR: 1,
                 Vips.BandFormat.USHORT: 2,
                 Vips.BandFormat.UINT: 4,
                 Vips.BandFormat.CHAR: 1,
                 Vips.BandFormat.SHORT: 2,
                 Vips.BandFormat.INT: 4,
                 Vips.BandFormat.FLOAT: 4,
                 Vips.BandFormat.DOUBLE: 8,
                 Vips.BandFormat.COMPLEX: 8,
                 Vips.BandFormat.DPCOMPLEX: 16}

rot45_angles = [Vips.Angle45.D0,
                Vips.Angle45.D45,
                Vips.Angle45.D90,
                Vips.Angle45.D135,
                Vips.Angle45.D180,
                Vips.Angle45.D225,
                Vips.Angle45.D270,
                Vips.Angle45.D315]

rot45_angle_bonds = [Vips.Angle45.D0,
                     Vips.Angle45.D315,
                     Vips.Angle45.D270,
                     Vips.Angle45.D225,
                     Vips.Angle45.D180,
                     Vips.Angle45.D135,
                     Vips.Angle45.D90,
                     Vips.Angle45.D45]

rot_angles = [Vips.Angle.D0,
              Vips.Angle.D90,
              Vips.Angle.D180,
              Vips.Angle.D270]

rot_angle_bonds = [Vips.Angle.D0,
                   Vips.Angle.D270,
                   Vips.Angle.D180,
                   Vips.Angle.D90]

# an expanding zip ... if either of the args is not a list, duplicate it down
# the other
def zip_expand(x, y):
    if isinstance(x, list) and isinstance(y, list):
        if len(x) != len(y):
            raise Vips.Error("zip_expand list args not equal length")
        return list(zip(x, y))
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
        a = im(x, y)
        v1 = fn(a)
        im2 = fn(im)
        v2 = im2(x, y)
        self.assertAlmostEqualObjects(v1, v2, msg = message)

    # run a function on a pair of images and on a pair of pixels, the results 
    # should match 
    def run_cmp_binary(self, message, left, right, x, y, fn):
        a = left(x, y)
        b = right(x, y)
        v1 = fn(a, b)
        after = fn(left, right)
        v2 = after(x, y)
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
        [self.run_testunary(fn.__name__ + (' %s' % y), x.cast(y), fn)
         for x in images for y in fmt]

    def run_binary(self, images, fn, fmt = all_formats):
        [self.run_testbinary(fn.__name__ + (' %s %s' % (y, z)), 
                             x.cast(y), x.cast(z), fn)
         for x in images for y in fmt for z in fmt]

    def setUp(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5, reject = True, optical = True)
        self.colour = im * [1, 2, 3] + [2, 3, 4]
        self.mono = self.colour[1]
        self.all_images = [self.mono, self.colour]

    def test_band_and(self):
        def band_and(x):
            if isinstance(x, Vips.Image):
                return x.bandand()
            else:
                return [reduce(lambda a, b: int(a) & int(b), x)]

        self.run_unary(self.all_images, band_and, fmt = int_formats)

    def test_band_or(self):
        def band_or(x):
            if isinstance(x, Vips.Image):
                return x.bandor()
            else:
                return [reduce(lambda a, b: int(a) | int(b), x)]

        self.run_unary(self.all_images, band_or, fmt = int_formats)

    def test_band_eor(self):
        def band_eor(x):
            if isinstance(x, Vips.Image):
                return x.bandeor()
            else:
                return [reduce(lambda a, b: int(a) ^ int(b), x)]

        self.run_unary(self.all_images, band_eor, fmt = int_formats)

    def test_bandjoin(self):
        def bandjoin(x, y):
            if isinstance(x, Vips.Image) and isinstance(y, Vips.Image):
                return x.bandjoin(y)
            else:
                return x + y

        self.run_binary(self.all_images, bandjoin)

    def test_bandjoin_const(self):
        x = self.colour.bandjoin(1)
        self.assertEqual(x.bands, 4)
        self.assertEqual(x[3].avg(), 1)

        x = self.colour.bandjoin([1,2])
        self.assertEqual(x.bands, 5)
        self.assertEqual(x[3].avg(), 1)
        self.assertEqual(x[4].avg(), 2)

    def test_bandmean(self):
        def bandmean(x):
            if isinstance(x, Vips.Image):
                return x.bandmean()
            else:
                return [sum(x) // len(x)]

        self.run_unary(self.all_images, bandmean, fmt = noncomplex_formats)

    def test_bandrank(self):
        def median(x, y):
            joined = [[a, b] for a, b in zip(x, y)]
            # .sort() isn't a function, so we have to run this as a separate
            # pass
            [x.sort() for x in joined]
            return [x[len(x) // 2] for x in joined]

        def bandrank(x, y):
            if isinstance(x, Vips.Image) and isinstance(y, Vips.Image):
                return x.bandrank([y])
            else:
                return median(x, y)

        self.run_binary(self.all_images, bandrank, fmt = noncomplex_formats)

        # we can mix images and constants, and set the index arg
        a = self.mono.bandrank([2], index = 0)
        b = (self.mono < 2).ifthenelse(self.mono, 2)
        self.assertEqual((a - b).abs().min(), 0)

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
        x = self.colour.copy(coding = Vips.Coding.NONE)
        self.assertEqual(x.coding, Vips.Coding.NONE)

    def test_bandfold(self):
        x = self.mono.bandfold()
        self.assertEqual(x.width, 1)
        self.assertEqual(x.bands, self.mono.width)

        y = x.bandunfold()
        self.assertEqual(y.width, self.mono.width)
        self.assertEqual(y.bands, 1)
        self.assertEqual(x.avg(), y.avg())

        x = self.mono.bandfold(factor = 2)
        self.assertEqual(x.width, self.mono.width / 2)
        self.assertEqual(x.bands, 2)

        y = x.bandunfold(factor = 2)
        self.assertEqual(y.width, self.mono.width)
        self.assertEqual(y.bands, 1)
        self.assertEqual(x.avg(), y.avg())

    def test_byteswap(self):
        x = self.mono.cast("ushort")
        y = x.byteswap().byteswap()
        self.assertEqual(x.width, y.width)
        self.assertEqual(x.height, y.height)
        self.assertEqual(x.bands, y.bands)
        self.assertEqual(x.avg(), y.avg())

    def test_embed(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40)
            pixel = im(10, 10)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])
            pixel = im(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])
            pixel = im(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.COPY)
            pixel = im(10, 10)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])
            pixel = im(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.BACKGROUND,
                            background = [7, 8, 9])
            pixel = im(10, 10)
            self.assertAlmostEqualObjects(pixel, [7, 8, 9])
            pixel = im(im.width - 10, im.height - 10)
            self.assertAlmostEqualObjects(pixel, [7, 8, 9])

            im = test.embed(20, 20, 
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend = Vips.Extend.WHITE)
            pixel = im(10, 10)
            # uses 255 in all bytes of ints, 255.0 for float
            pixel = [int(x) & 0xff for x in pixel]
            self.assertAlmostEqualObjects(pixel, [255, 255, 255])
            pixel = im(im.width - 10, im.height - 10)
            pixel = [int(x) & 0xff for x in pixel]
            self.assertAlmostEqualObjects(pixel, [255, 255, 255])

    def test_extract(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.extract_area(25, 25, 10, 10)

            pixel = sub(5, 5)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.extract_band(1, n = 2)

            pixel = sub(30, 30)
            self.assertAlmostEqualObjects(pixel, [3, 4])

    def test_slice(self):
        test = self.colour
        bands = [x.avg() for x in test]

        x = test[0].avg()
        self.assertEqual(x, bands[0])

        x = test[-1].avg()
        self.assertAlmostEqualObjects(x, bands[2])

        x = [i.avg() for i in test[1:3]]
        self.assertAlmostEqualObjects(x, bands[1:3])

        x = [i.avg() for i in test[1:-1]]
        self.assertAlmostEqualObjects(x, bands[1:-1])

        x = [i.avg() for i in test[:2]]
        self.assertAlmostEqualObjects(x, bands[:2])

        x = [i.avg() for i in test[1:]]
        self.assertAlmostEqualObjects(x, bands[1:])

        x = [i.avg() for i in test[-1]]
        self.assertAlmostEqualObjects(x, bands[-1])

    def test_crop(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test(30, 30)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

            sub = test.crop(25, 25, 10, 10)

            pixel = sub(5, 5)
            self.assertAlmostEqualObjects(pixel, [2, 3, 4])

    def test_falsecolour(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.falsecolour()

            self.assertEqual(im.width, test.width)
            self.assertEqual(im.height, test.height)
            self.assertEqual(im.bands, 3)

            pixel = im(30, 30)
            self.assertAlmostEqualObjects(pixel, [20, 0, 41])

    def test_flatten(self):
        for fmt in unsigned_formats + [Vips.BandFormat.SHORT, 
                Vips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            nalpha = mx - alpha
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) * alpha / mx for x in pixel[:-1]]

            im = test.flatten()

            self.assertEqual(im.bands, 3)
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                self.assertLess(abs(x - y), 2)

            im = test.flatten(background = [100, 100, 100])

            pixel = test(30, 30)
            predict = [int(x) * alpha / mx + (100 * nalpha) / mx
                       for x in pixel[:-1]]

            self.assertEqual(im.bands, 3)
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                self.assertLess(abs(x - y), 2)

    def test_premultiply(self):
        for fmt in unsigned_formats + [Vips.BandFormat.SHORT, 
                Vips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            nalpha = mx - alpha
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) * alpha / mx for x in pixel[:-1]] + [alpha]

            im = test.premultiply()

            self.assertEqual(im.bands, test.bands)
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                self.assertLess(abs(x - y), 2)

    def test_unpremultiply(self):
        for fmt in unsigned_formats + [Vips.BandFormat.SHORT, 
                Vips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            nalpha = mx - alpha
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) / (alpha / mx) for x in pixel[:-1]] + [alpha]

            im = test.unpremultiply()

            self.assertEqual(im.bands, test.bands)
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                self.assertLess(abs(x - y), 2)

    def test_flip(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            result = test.fliphor()
            result = result.flipver()
            result = result.fliphor()
            result = result.flipver()

            diff = (test - result).abs().max()

            self.assertEqual(diff, 0)

    def test_gamma(self):
        exponent = 2.4
        for fmt in noncomplex_formats:
            mx = max_value[fmt]
            test = (self.colour + mx / 2.0).cast(fmt)

            norm = mx ** exponent / mx
            result = test.gamma()
            before = test(30, 30)
            after = result(30, 30)
            predict = [x ** exponent / norm for x in before]
            for a, b in zip(after, predict):
                # ie. less than 1% error, rounding on 7-bit images means this is
                # all we can expect
                self.assertLess(abs(a - b), mx / 100.0)

        exponent = 1.2
        for fmt in noncomplex_formats:
            mx = max_value[fmt]
            test = (self.colour + mx / 2.0).cast(fmt)

            norm = mx ** exponent / mx
            result = test.gamma(exponent = 1.0 / 1.2)
            before = test(30, 30)
            after = result(30, 30)
            predict = [x ** exponent / norm for x in before]
            for a, b in zip(after, predict):
                # ie. less than 1% error, rounding on 7-bit images means this is
                # all we can expect
                self.assertLess(abs(a - b), mx / 100.0)

    def test_grid(self):
        test = self.colour.replicate(1, 12)
        self.assertEqual(test.width, self.colour.width)
        self.assertEqual(test.height, self.colour.height * 12)

        for fmt in all_formats:
            im = test.cast(fmt)
            result = im.grid(test.width, 3, 4)
            self.assertEqual(result.width, self.colour.width * 3)
            self.assertEqual(result.height, self.colour.height * 4)

            before = im(10, 10)
            after = result(10 + test.width * 2, 10 + test.width * 2)
            self.assertAlmostEqualObjects(before, after)

            before = im(50, 50)
            after = result(50 + test.width * 2, 50 + test.width * 2)
            self.assertAlmostEqualObjects(before, after)

    def test_ifthenelse(self):
        test = self.mono > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.colour + 10).cast(x)
                e = self.colour.cast(y)
                r = test.ifthenelse(t, e)

                self.assertEqual(r.width, self.colour.width)
                self.assertEqual(r.height, self.colour.height)
                self.assertEqual(r.bands, self.colour.bands)

                predict = e(10, 10)
                result = r(10, 10)
                self.assertAlmostEqualObjects(result, predict)

                predict = t(50, 50)
                result = r(50, 50)
                self.assertAlmostEqualObjects(result, predict)

        test = self.colour > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.mono + 10).cast(x)
                e = self.mono.cast(y)
                r = test.ifthenelse(t, e)

                self.assertEqual(r.width, self.colour.width)
                self.assertEqual(r.height, self.colour.height)
                self.assertEqual(r.bands, self.colour.bands)

                cp = test(10, 10)
                tp = t(10, 10) * 3
                ep = e(10, 10) * 3
                predict = [te if ce != 0 else ee 
                           for ce, te, ee in zip(cp, tp, ep)]
                result = r(10, 10)
                self.assertAlmostEqualObjects(result, predict)

                cp = test(50, 50)
                tp = t(50, 50) * 3
                ep = e(50, 50) * 3
                predict = [te if ce != 0 else ee 
                           for ce, te, ee in zip(cp, tp, ep)]
                result = r(50, 50)
                self.assertAlmostEqualObjects(result, predict)

        test = self.colour > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.mono + 10).cast(x)
                e = self.mono.cast(y)
                r = test.ifthenelse(t, e, blend = True)

                self.assertEqual(r.width, self.colour.width)
                self.assertEqual(r.height, self.colour.height)
                self.assertEqual(r.bands, self.colour.bands)

                result = r(10, 10)
                self.assertAlmostEqualObjects(result, [3, 3, 13])

        test = self.mono > 3
        r = test.ifthenelse([1, 2, 3], self.colour)
        self.assertEqual(r.width, self.colour.width)
        self.assertEqual(r.height, self.colour.height)
        self.assertEqual(r.bands, self.colour.bands)
        self.assertEqual(r.format, self.colour.format)
        self.assertEqual(r.interpretation, self.colour.interpretation)
        result = r(10, 10)
        self.assertAlmostEqualObjects(result, [2, 3, 4])
        result = r(50, 50)
        self.assertAlmostEqualObjects(result, [1, 2, 3])

        test = self.mono
        r = test.ifthenelse([1, 2, 3], self.colour, blend = True)
        self.assertEqual(r.width, self.colour.width)
        self.assertEqual(r.height, self.colour.height)
        self.assertEqual(r.bands, self.colour.bands)
        self.assertEqual(r.format, self.colour.format)
        self.assertEqual(r.interpretation, self.colour.interpretation)
        result = r(10, 10)
        self.assertAlmostEqualObjects(result, [2, 3, 4], places = 1)
        result = r(50, 50)
        self.assertAlmostEqualObjects(result, [3.0, 4.9, 6.9], places = 1)

    def test_insert(self):
        for x in all_formats:
            for y in all_formats:
                main = self.mono.cast(x)
                sub = self.colour.cast(y)
                r = main.insert(sub, 10, 10)

                self.assertEqual(r.width, main.width)
                self.assertEqual(r.height, main.height)
                self.assertEqual(r.bands, sub.bands)

                a = r(10, 10)
                b = sub(0, 0)
                self.assertAlmostEqualObjects(a, b)

                a = r(0, 0)
                b = main(0, 0) * 3
                self.assertAlmostEqualObjects(a, b)

        for x in all_formats:
            for y in all_formats:
                main = self.mono.cast(x)
                sub = self.colour.cast(y)
                r = main.insert(sub, 10, 10, expand = True, background = 100)

                self.assertEqual(r.width, main.width + 10)
                self.assertEqual(r.height, main.height + 10)
                self.assertEqual(r.bands, sub.bands)

                a = r(r.width - 5, 5)
                self.assertAlmostEqualObjects(a, [100, 100, 100])

    def test_arrayjoin(self):
        max_width = 0
        max_height = 0
        max_bands = 0
        for image in self.all_images:
            if image.width > max_width:
                max_width = image.width
            if image.height > max_height:
                max_height = image.height
            if image.bands > max_bands:
                max_bands = image.bands

        im = Vips.Image.arrayjoin(self.all_images)
        self.assertEqual(im.width, max_width * len(self.all_images))
        self.assertEqual(im.height, max_height)
        self.assertEqual(im.bands, max_bands)

        im = Vips.Image.arrayjoin(self.all_images, across = 1)
        self.assertEqual(im.width, max_width)
        self.assertEqual(im.height, max_height * len(self.all_images))
        self.assertEqual(im.bands, max_bands)

        im = Vips.Image.arrayjoin(self.all_images, shim = 10)
        self.assertEqual(im.width, max_width * len(self.all_images) + 
                         10 * (len(self.all_images) - 1))
        self.assertEqual(im.height, max_height)
        self.assertEqual(im.bands, max_bands)

    def test_msb(self):
        for fmt in unsigned_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb()

            before = test(10, 10)
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(10, 10)
            self.assertAlmostEqualObjects(result, predict)

            before = test(50, 50)
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(50, 50)
            self.assertAlmostEqualObjects(result, predict)

        for fmt in signed_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb()

            before = test(10, 10)
            predict = [128 + (int(x) >> ((size - 1) * 8)) for x in before]
            result = im(10, 10)
            self.assertAlmostEqualObjects(result, predict)

            before = test(50, 50)
            predict = [128 + (int(x) >> ((size - 1) * 8)) for x in before]
            result = im(50, 50)
            self.assertAlmostEqualObjects(result, predict)

        for fmt in unsigned_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb(band = 1)

            before = [test(10, 10)[1]]
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(10, 10)
            self.assertAlmostEqualObjects(result, predict)

            before = [test(50, 50)[1]]
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(50, 50)
            self.assertAlmostEqualObjects(result, predict)

    def test_recomb(self):
        array = [[0.2, 0.5, 0.3]]

        def recomb(x):
            if isinstance(x, Vips.Image):
                return x.recomb(array)
            else:
                sum = 0
                for i, c in zip(array[0], x):
                    sum += i * c
                return [sum]

        self.run_unary([self.colour], recomb, fmt = noncomplex_formats)

    def test_replicate(self):
        for fmt in all_formats:
            im = self.colour.cast(fmt)

            test = im.replicate(10, 10)
            self.assertEqual(test.width, self.colour.width * 10)
            self.assertEqual(test.height, self.colour.height * 10)

            before = im(10, 10)
            after = test(10 + im.width * 2, 10 + im.width * 2)
            self.assertAlmostEqualObjects(before, after)

            before = im(50, 50)
            after = test(50 + im.width * 2, 50 + im.width * 2)
            self.assertAlmostEqualObjects(before, after)

    def test_rot45(self):
        # test has a quarter-circle in the bottom right
        test = self.colour.crop(0, 0, 51, 51)
        for fmt in all_formats:
            im = test.cast(fmt)

            im2 = im.rot45()
            before = im(50, 50)
            after = im2(25, 50)
            self.assertAlmostEqualObjects(before, after)

            for a, b in zip(rot45_angles, rot45_angle_bonds):
                im2 = im.rot45(angle = a)
                after = im2.rot45(angle = b)
                diff = (after - im).abs().max()
                self.assertEqual(diff, 0)

    def test_rot(self):
        # test has a quarter-circle in the bottom right
        test = self.colour.crop(0, 0, 51, 51)
        for fmt in all_formats:
            im = test.cast(fmt)

            im2 = im.rot(Vips.Angle.D90)
            before = im(50, 50)
            after = im2(0, 50)
            self.assertAlmostEqualObjects(before, after)

            for a, b in zip(rot_angles, rot_angle_bonds):
                im2 = im.rot(a)
                after = im2.rot(b)
                diff = (after - im).abs().max()
                self.assertEqual(diff, 0)

    def test_scale(self):
        for fmt in noncomplex_formats:
            test = self.colour.cast(fmt)

            im = test.scale()
            self.assertEqual(im.max(), 255)
            self.assertEqual(im.min(), 0)

            im = test.scale(log = True)
            self.assertEqual(im.max(), 255)

    def test_subsample(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.subsample(3, 3)
            self.assertEqual(im.width, test.width // 3)
            self.assertEqual(im.height, test.height // 3)

            before = test(60, 60)
            after = im(20, 20)
            self.assertAlmostEqualObjects(before, after)

    def test_zoom(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.zoom(3, 3)
            self.assertEqual(im.width, test.width * 3)
            self.assertEqual(im.height, test.height * 3)

            before = test(50, 50)
            after = im(150, 150)
            self.assertAlmostEqualObjects(before, after)

    def test_wrap(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.wrap()
            self.assertEqual(im.width, test.width)
            self.assertEqual(im.height, test.height)

            before = test(0, 0)
            after = im(50, 50)
            self.assertAlmostEqualObjects(before, after)

            before = test(50, 50)
            after = im(0, 0)
            self.assertAlmostEqualObjects(before, after)

if __name__ == '__main__':
    unittest.main()
