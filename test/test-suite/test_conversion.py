# vim: set fileencoding=utf-8 :
import filecmp
from functools import reduce

import os
import pytest
import tempfile
import shutil

import pyvips
from helpers import IMAGES, JPEG_FILE, unsigned_formats, \
    signed_formats, float_formats, int_formats, \
    noncomplex_formats, all_formats, max_value, \
    sizeof_format, rot45_angles, rot45_angle_bonds, \
    rot_angles, rot_angle_bonds, run_cmp, run_cmp2, \
    assert_almost_equal_objects, temp_filename


class TestConversion:
    tempdir = None
    
    # run a function on an image,
    # 50,50 and 10,10 should have different values on the test image
    # don't loop over band elements
    def run_image_pixels(self, message, im, fn):
        run_cmp(message, im, 50, 50, fn)
        run_cmp(message, im, 10, 10, fn)

    # run a function on a pair of images
    # 50,50 and 10,10 should have different values on the test image
    # don't loop over band elements
    def run_image_pixels2(self, message, left, right, fn):
        run_cmp2(message, left, right, 50, 50, fn)
        run_cmp2(message, left, right, 10, 10, fn)

    def run_unary(self, images, fn, fmt=all_formats):
        [self.run_image_pixels(fn.__name__ + (' %s' % y), x.cast(y), fn)
         for x in images for y in fmt]

    def run_binary(self, images, fn, fmt=all_formats):
        [self.run_image_pixels2(fn.__name__ + (' %s %s' % (y, z)),
                                x.cast(y), x.cast(z), fn)
         for x in images for y in fmt for z in fmt]

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()
        im = pyvips.Image.mask_ideal(100, 100, 0.5,
                                     reject=True, optical=True)
        cls.colour = (im * [1, 2, 3] + [2, 3, 4]).copy(interpretation="srgb")
        cls.mono = cls.colour[1].copy(interpretation="b-w")
        cls.all_images = [cls.mono, cls.colour]
        cls.image = pyvips.Image.jpegload(JPEG_FILE)

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir, ignore_errors=True)
        cls.colour = None
        cls.mono = None
        cls.image = None
        cls.all_images = None

    def test_cast(self):
        # casting negative pixels to an unsigned format should clip to zero
        for signed in signed_formats: 
            im = (pyvips.Image.black(1, 1) - 10).cast(signed)
            for unsigned in unsigned_formats:
                im2 = im.cast(unsigned)
                assert im2.avg() == 0

        # casting very positive pixels to a signed format should clip to max
        im = (pyvips.Image.black(1, 1) + max_value["uint"]).cast("uint")
        assert im.avg() == max_value["uint"]
        im2 = im.cast("int")
        assert im2.avg() == max_value["int"]
        im = (pyvips.Image.black(1, 1) + max_value["ushort"]).cast("ushort")
        im2 = im.cast("short")
        assert im2.avg() == max_value["short"]
        im = (pyvips.Image.black(1, 1) + max_value["uchar"]).cast("uchar")
        im2 = im.cast("char")
        assert im2.avg() == max_value["char"]

    def test_band_and(self):
        def band_and(x):
            if isinstance(x, pyvips.Image):
                return x.bandand()
            else:
                return [reduce(lambda a, b: int(a) & int(b), x)]

        self.run_unary(self.all_images, band_and, fmt=int_formats)

    def test_band_or(self):
        def band_or(x):
            if isinstance(x, pyvips.Image):
                return x.bandor()
            else:
                return [reduce(lambda a, b: int(a) | int(b), x)]

        self.run_unary(self.all_images, band_or, fmt=int_formats)

    def test_band_eor(self):
        def band_eor(x):
            if isinstance(x, pyvips.Image):
                return x.bandeor()
            else:
                return [reduce(lambda a, b: int(a) ^ int(b), x)]

        self.run_unary(self.all_images, band_eor, fmt=int_formats)

    def test_bandjoin(self):
        def bandjoin(x, y):
            if isinstance(x, pyvips.Image) and isinstance(y, pyvips.Image):
                return x.bandjoin(y)
            else:
                return x + y

        self.run_binary(self.all_images, bandjoin)

    def test_bandjoin_const(self):
        x = self.colour.bandjoin(1)
        assert x.bands == 4
        assert x[3].avg() == 1

        x = self.colour.bandjoin([1, 2])
        assert x.bands == 5
        assert x[3].avg() == 1
        assert x[4].avg() == 2

    def test_bandmean(self):
        def bandmean(x):
            if isinstance(x, pyvips.Image):
                return x.bandmean()
            else:
                return [sum(x) // len(x)]

        self.run_unary(self.all_images, bandmean, fmt=noncomplex_formats)

    def test_bandrank(self):
        def median(x, y):
            joined = [[a, b] for a, b in zip(x, y)]
            # .sort() isn't a function, so we have to run this as a separate
            # pass
            [z.sort() for z in joined]
            return [z[len(z) // 2] for z in joined]

        def bandrank(x, y):
            if isinstance(x, pyvips.Image) and isinstance(y, pyvips.Image):
                return x.bandrank([y])
            else:
                return median(x, y)

        self.run_binary(self.all_images, bandrank, fmt=noncomplex_formats)

        # we can mix images and constants, and set the index arg
        a = self.mono.bandrank([2], index=0)
        b = (self.mono < 2).ifthenelse(self.mono, 2)
        assert (a - b).abs().min() == 0

    def test_cache(self):
        def cache(x):
            if isinstance(x, pyvips.Image):
                return x.cache()
            else:
                return x

        self.run_unary(self.all_images, cache)

    def test_copy(self):
        x = self.colour.copy(interpretation=pyvips.Interpretation.LAB)
        assert x.interpretation == pyvips.Interpretation.LAB
        x = self.colour.copy(xres=42)
        assert x.xres == 42
        x = self.colour.copy(yres=42)
        assert x.yres == 42
        x = self.colour.copy(xoffset=42)
        assert x.xoffset == 42
        x = self.colour.copy(yoffset=42)
        assert x.yoffset == 42
        x = self.colour.copy(coding=pyvips.Coding.NONE)
        assert x.coding == pyvips.Coding.NONE

    def test_bandfold(self):
        x = self.mono.bandfold()
        assert x.width == 1
        assert x.bands == self.mono.width

        y = x.bandunfold()
        assert y.width == self.mono.width
        assert y.bands == 1
        assert x.avg() == y.avg()

        x = self.mono.bandfold(factor=2)
        assert x.width == self.mono.width / 2
        assert x.bands == 2

        y = x.bandunfold(factor=2)
        assert y.width == self.mono.width
        assert y.bands == 1
        assert x.avg() == y.avg()

    def test_byteswap(self):
        x = self.mono.cast("ushort")
        y = x.byteswap().byteswap()
        assert x.width == y.width
        assert x.height == y.height
        assert x.bands == y.bands
        assert x.avg() == y.avg()

    def test_embed(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.embed(20, 20,
                            self.colour.width + 40,
                            self.colour.height + 40)
            pixel = im(10, 10)
            assert_almost_equal_objects(pixel, [0, 0, 0])
            pixel = im(30, 30)
            assert_almost_equal_objects(pixel, [2, 3, 4])
            pixel = im(im.width - 10, im.height - 10)
            assert_almost_equal_objects(pixel, [0, 0, 0])

            im = test.embed(20, 20,
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend=pyvips.Extend.COPY)
            pixel = im(10, 10)
            assert_almost_equal_objects(pixel, [2, 3, 4])
            pixel = im(im.width - 10, im.height - 10)
            assert_almost_equal_objects(pixel, [2, 3, 4])

            im = test.embed(20, 20,
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend=pyvips.Extend.BACKGROUND,
                            background=[7, 8, 9])
            pixel = im(10, 10)
            assert_almost_equal_objects(pixel, [7, 8, 9])
            pixel = im(im.width - 10, im.height - 10)
            assert_almost_equal_objects(pixel, [7, 8, 9])

            im = test.embed(20, 20,
                            self.colour.width + 40,
                            self.colour.height + 40,
                            extend=pyvips.Extend.WHITE)
            pixel = im(10, 10)
            # uses 255 in all bytes of ints, 255.0 for float
            pixel = [int(x) & 0xff for x in pixel]
            assert_almost_equal_objects(pixel, [255, 255, 255])
            pixel = im(im.width - 10, im.height - 10)
            pixel = [int(x) & 0xff for x in pixel]
            assert_almost_equal_objects(pixel, [255, 255, 255])

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "gravity") == 0,
                        reason="no gravity in this vips, skipping test")
    def test_gravity(self):
        im = pyvips.Image.black(1, 1) + 255

        positions = [
            ['centre', 1, 1],
            ['north', 1, 0],
            ['south', 1, 2],
            ['east', 2, 1],
            ['west', 0, 1],
            ['north-east', 2, 0],
            ['south-east', 2, 2],
            ['south-west', 0, 2],
            ['north-west', 0, 0]
        ]

        for direction, x, y in positions:
            im2 = im.gravity(direction, 3, 3)
            assert_almost_equal_objects(im2(x, y), [255])
            assert_almost_equal_objects(im2.avg(), 255.0 / 9.0)

    def test_extract(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test(30, 30)
            assert_almost_equal_objects(pixel, [2, 3, 4])

            sub = test.extract_area(25, 25, 10, 10)

            pixel = sub(5, 5)
            assert_almost_equal_objects(pixel, [2, 3, 4])

            sub = test.extract_band(1, n=2)

            pixel = sub(30, 30)
            assert_almost_equal_objects(pixel, [3, 4])

    def test_slice(self):
        test = self.colour
        bands = [x.avg() for x in test]

        x = test[0].avg()
        assert x == bands[0]

        x = test[-1].avg()
        assert_almost_equal_objects(x, bands[2])

        x = [i.avg() for i in test[1:3]]
        assert_almost_equal_objects(x, bands[1:3])

        x = [i.avg() for i in test[1:-1]]
        assert_almost_equal_objects(x, bands[1:-1])

        x = [i.avg() for i in test[:2]]
        assert_almost_equal_objects(x, bands[:2])

        x = [i.avg() for i in test[1:]]
        assert_almost_equal_objects(x, bands[1:])

        x = [i.avg() for i in test[-1]]
        assert_almost_equal_objects(x, bands[-1])

    def test_crop(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            pixel = test(30, 30)
            assert_almost_equal_objects(pixel, [2, 3, 4])

            sub = test.crop(25, 25, 10, 10)

            pixel = sub(5, 5)
            assert_almost_equal_objects(pixel, [2, 3, 4])

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "smartcrop") == 0,
                        reason="no smartcrop, skipping test")
    def test_smartcrop(self):
        test = self.image.smartcrop(100, 100)
        assert test.width == 100
        assert test.height == 100

    def test_falsecolour(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.falsecolour()

            assert im.width == test.width
            assert im.height == test.height
            assert im.bands == 3

            pixel = im(30, 30)
            assert_almost_equal_objects(pixel, [20, 0, 41])

    def test_flatten(self):
        for fmt in unsigned_formats + [pyvips.BandFormat.SHORT,
                                       pyvips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            nalpha = mx - alpha
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) * alpha / mx for x in pixel[:-1]]

            im = test.flatten()

            assert im.bands == 3
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                assert abs(x - y) < 2

            im = test.flatten(background=[100, 100, 100])

            pixel = test(30, 30)
            predict = [int(x) * alpha / mx + (100 * nalpha) / mx
                       for x in pixel[:-1]]

            assert im.bands == 3
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                assert abs(x - y) < 2

    def test_premultiply(self):
        for fmt in unsigned_formats + [pyvips.BandFormat.SHORT,
                                       pyvips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) * alpha / mx for x in pixel[:-1]] + [alpha]

            im = test.premultiply()

            assert im.bands == test.bands
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                assert abs(x - y) < 2

    @pytest.mark.skipif(pyvips.type_find("VipsConversion", "composite") == 0,
                        reason="no composite support, skipping test")
    def test_composite(self):
        # 50% transparent image
        overlay = self.colour.bandjoin(128)
        base = self.colour + 100
        comp = base.composite(overlay, "over")

        assert_almost_equal_objects(comp(0, 0), [51.8, 52.8, 53.8, 255],
                                    threshold=0.1)

    def test_unpremultiply(self):
        for fmt in unsigned_formats + [pyvips.BandFormat.SHORT,
                                       pyvips.BandFormat.INT] + float_formats:
            mx = 255
            alpha = mx / 2.0
            test = self.colour.bandjoin(alpha).cast(fmt)
            pixel = test(30, 30)

            predict = [int(x) / (alpha / mx) for x in pixel[:-1]] + [alpha]

            im = test.unpremultiply()

            assert im.bands == test.bands
            pixel = im(30, 30)
            for x, y in zip(pixel, predict):
                # we use float arithetic for int and uint, so the rounding
                # differs ... don't require huge accuracy
                assert abs(x - y) < 2

    def test_flip(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            result = test.fliphor()
            result = result.flipver()
            result = result.fliphor()
            result = result.flipver()

            diff = (test - result).abs().max()

            assert diff == 0

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
                # ie. less than 1% error, rounding on 7-bit images
                # means this is all we can expect
                assert abs(a - b) < mx / 100.0

        exponent = 1.2
        for fmt in noncomplex_formats:
            mx = max_value[fmt]
            test = (self.colour + mx / 2.0).cast(fmt)

            norm = mx ** exponent / mx
            result = test.gamma(exponent=1.0 / 1.2)
            before = test(30, 30)
            after = result(30, 30)
            predict = [x ** exponent / norm for x in before]
            for a, b in zip(after, predict):
                # ie. less than 1% error, rounding on 7-bit images
                # means this is all we can expect
                assert abs(a - b) < mx / 100.0

    def test_grid(self):
        test = self.colour.replicate(1, 12)
        assert test.width == self.colour.width
        assert test.height == self.colour.height * 12

        for fmt in all_formats:
            im = test.cast(fmt)
            result = im.grid(test.width, 3, 4)
            assert result.width == self.colour.width * 3
            assert result.height == self.colour.height * 4

            before = im(10, 10)
            after = result(10 + test.width * 2, 10 + test.width * 2)
            assert_almost_equal_objects(before, after)

            before = im(50, 50)
            after = result(50 + test.width * 2, 50 + test.width * 2)
            assert_almost_equal_objects(before, after)

    def test_ifthenelse(self):
        test = self.mono > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.colour + 10).cast(x)
                e = self.colour.cast(y)
                r = test.ifthenelse(t, e)

                assert r.width == self.colour.width
                assert r.height == self.colour.height
                assert r.bands == self.colour.bands

                predict = e(10, 10)
                result = r(10, 10)
                assert_almost_equal_objects(result, predict)

                predict = t(50, 50)
                result = r(50, 50)
                assert_almost_equal_objects(result, predict)

        test = self.colour > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.mono + 10).cast(x)
                e = self.mono.cast(y)
                r = test.ifthenelse(t, e)

                assert r.width == self.colour.width
                assert r.height == self.colour.height
                assert r.bands == self.colour.bands

                cp = test(10, 10)
                tp = t(10, 10) * 3
                ep = e(10, 10) * 3
                predict = [te if ce != 0 else ee
                           for ce, te, ee in zip(cp, tp, ep)]
                result = r(10, 10)
                assert_almost_equal_objects(result, predict)

                cp = test(50, 50)
                tp = t(50, 50) * 3
                ep = e(50, 50) * 3
                predict = [te if ce != 0 else ee
                           for ce, te, ee in zip(cp, tp, ep)]
                result = r(50, 50)
                assert_almost_equal_objects(result, predict)

        test = self.colour > 3
        for x in all_formats:
            for y in all_formats:
                t = (self.mono + 10).cast(x)
                e = self.mono.cast(y)
                r = test.ifthenelse(t, e, blend=True)

                assert r.width == self.colour.width
                assert r.height == self.colour.height
                assert r.bands == self.colour.bands

                result = r(10, 10)
                assert_almost_equal_objects(result, [3, 3, 13])

        test = self.mono > 3
        r = test.ifthenelse([1, 2, 3], self.colour)
        assert r.width == self.colour.width
        assert r.height == self.colour.height
        assert r.bands == self.colour.bands
        assert r.format == self.colour.format
        assert r.interpretation == self.colour.interpretation
        result = r(10, 10)
        assert_almost_equal_objects(result, [2, 3, 4])
        result = r(50, 50)
        assert_almost_equal_objects(result, [1, 2, 3])

        test = self.mono
        r = test.ifthenelse([1, 2, 3], self.colour, blend=True)
        assert r.width == self.colour.width
        assert r.height == self.colour.height
        assert r.bands == self.colour.bands
        assert r.format == self.colour.format
        assert r.interpretation == self.colour.interpretation
        result = r(10, 10)
        assert_almost_equal_objects(result, [2, 3, 4], threshold=0.1)
        result = r(50, 50)
        assert_almost_equal_objects(result, [3.0, 4.9, 6.9], threshold=0.1)

    def test_switch(self):
        x = pyvips.Image.grey(256, 256, uchar=True)

        # slice into two at 128, we should get 50% of pixels in each half
        index = pyvips.Image.switch([x < 128, x >= 128])
        assert index.avg() == 0.5

        # slice into four 
        index = pyvips.Image.switch([
            x < 64, 
            x >= 64 and x < 128,
            x >= 128 and x < 192,
            x >= 192
        ])
        assert index.avg() == 1.5

        # no match should return n + 1
        index = pyvips.Image.switch([x == 1000, x == 2000])
        assert index.avg() == 2

    def test_insert(self):
        for x in all_formats:
            for y in all_formats:
                main = self.mono.cast(x)
                sub = self.colour.cast(y)
                r = main.insert(sub, 10, 10)

                assert r.width == main.width
                assert r.height == main.height
                assert r.bands == sub.bands

                a = r(10, 10)
                b = sub(0, 0)
                assert_almost_equal_objects(a, b)

                a = r(0, 0)
                b = main(0, 0) * 3
                assert_almost_equal_objects(a, b)

        for x in all_formats:
            for y in all_formats:
                main = self.mono.cast(x)
                sub = self.colour.cast(y)
                r = main.insert(sub, 10, 10, expand=True, background=100)

                assert r.width == main.width + 10
                assert r.height == main.height + 10
                assert r.bands == sub.bands

                a = r(r.width - 5, 5)
                assert_almost_equal_objects(a, [100, 100, 100])

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

        im = pyvips.Image.arrayjoin(self.all_images)
        assert im.width == max_width * len(self.all_images)
        assert im.height == max_height
        assert im.bands == max_bands

        im = pyvips.Image.arrayjoin(self.all_images, across=1)
        assert im.width == max_width
        assert im.height == max_height * len(self.all_images)
        assert im.bands == max_bands

        im = pyvips.Image.arrayjoin(self.all_images, shim=10)
        assert im.width == max_width * len(self.all_images) + 10 * (len(self.all_images) - 1)  # noqa: E501
        assert im.height == max_height
        assert im.bands == max_bands

    def test_msb(self):
        for fmt in unsigned_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb()

            before = test(10, 10)
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(10, 10)
            assert_almost_equal_objects(result, predict)

            before = test(50, 50)
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(50, 50)
            assert_almost_equal_objects(result, predict)

        for fmt in signed_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb()

            before = test(10, 10)
            predict = [128 + (int(x) >> ((size - 1) * 8)) for x in before]
            result = im(10, 10)
            assert_almost_equal_objects(result, predict)

            before = test(50, 50)
            predict = [128 + (int(x) >> ((size - 1) * 8)) for x in before]
            result = im(50, 50)
            assert_almost_equal_objects(result, predict)

        for fmt in unsigned_formats:
            mx = max_value[fmt]
            size = sizeof_format[fmt]
            test = (self.colour + mx / 8.0).cast(fmt)
            im = test.msb(band=1)

            before = [test(10, 10)[1]]
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(10, 10)
            assert_almost_equal_objects(result, predict)

            before = [test(50, 50)[1]]
            predict = [int(x) >> ((size - 1) * 8) for x in before]
            result = im(50, 50)
            assert_almost_equal_objects(result, predict)

    def test_recomb(self):
        array = [[0.2, 0.5, 0.3]]

        def recomb(x):
            if isinstance(x, pyvips.Image):
                return x.recomb(array)
            else:
                sum = 0
                for i, c in zip(array[0], x):
                    sum += i * c
                return [sum]

        self.run_unary([self.colour], recomb, fmt=noncomplex_formats)

    def test_replicate(self):
        for fmt in all_formats:
            im = self.colour.cast(fmt)

            test = im.replicate(10, 10)
            assert test.width == self.colour.width * 10
            assert test.height == self.colour.height * 10

            before = im(10, 10)
            after = test(10 + im.width * 2, 10 + im.width * 2)
            assert_almost_equal_objects(before, after)

            before = im(50, 50)
            after = test(50 + im.width * 2, 50 + im.width * 2)
            assert_almost_equal_objects(before, after)

    def test_rot45(self):
        # test has a quarter-circle in the bottom right
        test = self.colour.crop(0, 0, 51, 51)
        for fmt in all_formats:
            im = test.cast(fmt)

            im2 = im.rot45()
            before = im(50, 50)
            after = im2(25, 50)
            assert_almost_equal_objects(before, after)

            for a, b in zip(rot45_angles, rot45_angle_bonds):
                im2 = im.rot45(angle=a)
                after = im2.rot45(angle=b)
                diff = (after - im).abs().max()
                assert diff == 0

    def test_rot(self):
        # test has a quarter-circle in the bottom right
        test = self.colour.crop(0, 0, 51, 51)
        for fmt in all_formats:
            im = test.cast(fmt)

            im2 = im.rot(pyvips.Angle.D90)
            before = im(50, 50)
            after = im2(0, 50)
            assert_almost_equal_objects(before, after)

            for a, b in zip(rot_angles, rot_angle_bonds):
                im2 = im.rot(a)
                after = im2.rot(b)
                diff = (after - im).abs().max()
                assert diff == 0

    def test_autorot(self):
        rotation_images = os.path.join(IMAGES, 'rotation')
        files = os.listdir(rotation_images)
        files.sort()

        meta = {
            0: {'w': 290, 'h': 442},
            1: {'w': 308, 'h': 410},
            2: {'w': 308, 'h': 410},
            3: {'w': 308, 'h': 410},
            4: {'w': 308, 'h': 410},
            5: {'w': 231, 'h': 308},
            6: {'w': 231, 'h': 308},
            7: {'w': 231, 'h': 308},
            8: {'w': 231, 'h': 308},
        }

        i = 0
        for f in files:
            if '.autorot.' not in f and not f.startswith('.'):
                source_filename = os.path.join(rotation_images, f)

                actual_filename = temp_filename(self.tempdir, '.jpg')

                pyvips.Image.new_from_file(source_filename).autorot().write_to_file(actual_filename)

                actual = pyvips.Image.new_from_file(actual_filename)

                assert actual.width == meta[i]['w']
                assert actual.height == meta[i]['h']
                assert actual.get('orientation') if actual.get_typeof('orientation') else None is None
                i = i + 1
       
    def test_scaleimage(self):
        for fmt in noncomplex_formats:
            test = self.colour.cast(fmt)

            im = test.scaleimage()
            assert im.max() == 255
            assert im.min() == 0

            im = test.scaleimage(log=True)
            assert im.max() == 255

    def test_subsample(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.subsample(3, 3)
            assert im.width == test.width // 3
            assert im.height == test.height // 3

            before = test(60, 60)
            after = im(20, 20)
            assert_almost_equal_objects(before, after)

    def test_zoom(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.zoom(3, 3)
            assert im.width == test.width * 3
            assert im.height == test.height * 3

            before = test(50, 50)
            after = im(150, 150)
            assert_almost_equal_objects(before, after)

    def test_wrap(self):
        for fmt in all_formats:
            test = self.colour.cast(fmt)

            im = test.wrap()
            assert im.width == test.width
            assert im.height == test.height

            before = test(0, 0)
            after = im(50, 50)
            assert_almost_equal_objects(before, after)

            before = test(50, 50)
            after = im(0, 0)
            assert_almost_equal_objects(before, after)


if __name__ == '__main__':
    pytest.main()
