#!/usr/bin/python

from __future__ import division
import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

Vips.leak_set(True)

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

class TestForeign(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        #print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def setUp(self):
        self.matlab_file = "images/sample.mat"
        self.jpeg_file = "images/IMG_4618.jpg"
        self.png_file = "images/sample.png"
        self.tiff_file = "images/sample.tif"
        self.profile_file = "images/sRGB.icm"
        self.analyze_file = "images/t00740_tr1_segm.hdr"
        self.gif_file = "images/cramps.gif"
        self.webp_file = "images/1.webp"
        self.exr_file = "images/sample.exr"
        self.fits_file = "images/WFPC2u5780205r_c0fx.fits"
        self.openslide_file = "images/CMU-1-Small-Region.svs"

        self.colour = Vips.Image.jpegload(self.jpeg_file)
        self.mono = self.colour.extract_band(1)
        self.rad = self.colour.float2rad()
        self.cmyk = self.colour.bandjoin(self.mono)
        self.cmyk = self.cmyk.copy(interpretation = Vips.Interpretation.CMYK)

    # we have test files for formats which have a clear standard
    def file_loader(self, loader, test_file, validate):
        im = Vips.call(loader, test_file)
        validate(self, im)
        im = Vips.Image.new_from_file(test_file)
        validate(self, im)

    def buffer_loader(self, loader, test_file, validate):
        with open(test_file, 'rb') as f:
            buf = f.read()

        im = Vips.call(loader, buf)
        validate(self, im)
        im = Vips.Image.new_from_buffer(buf, "")
        validate(self, im)

    def save_load(self, format, im):
        x = Vips.Image.new_temp_file(format)
        im.write(x)

        self.assertEqual(im.width, x.width)
        self.assertEqual(im.height, x.height)
        self.assertEqual(im.bands, x.bands)
        max_diff = (im - x).abs().max()
        self.assertEqual(max_diff, 0)

    def test_jpeg(self):
        if not Vips.type_find("VipsForeign", "jpegload"):
            print("no jpeg support in this vips, skipping test")
            return

        def jpeg_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [6, 5, 3])
            profile = im.get_value("icc-profile-data")
            self.assertEqual(len(profile), 1352)
            self.assertEqual(im.width, 1024)
            self.assertEqual(im.height, 768)
            self.assertEqual(im.bands, 3)

        self.file_loader("jpegload", self.jpeg_file, jpeg_valid)
        self.buffer_loader("jpegload_buffer", self.jpeg_file, jpeg_valid)
        self.save_load("%s.jpg", self.mono)
        self.save_load("%s.jpg", self.colour)

    def test_png(self):
        if not Vips.type_find("VipsForeign", "pngload"):
            print("no png support in this vips, skipping test")
            return

        def png_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("pngload", self.png_file, png_valid)
        self.buffer_loader("pngload_buffer", self.png_file, png_valid)
        self.save_load("%s.png", self.mono)
        self.save_load("%s.png", self.colour)

    def test_tiff(self):
        if not Vips.type_find("VipsForeign", "tiffload"):
            print("no tiff support in this vips, skipping test")
            return

        def tiff_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("tiffload", self.tiff_file, tiff_valid)
        self.buffer_loader("tiffload_buffer", self.tiff_file, tiff_valid)
        self.save_load("%s.tif", self.mono)
        self.save_load("%s.tif", self.colour)
        self.save_load("%s.tif", self.cmyk)

    def test_magickload(self):
        if not Vips.type_find("VipsForeign", "magickload"):
            print("no magick support in this vips, skipping test")
            return

        def gif_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqual(a, [33, 33, 33])
            self.assertEqual(im.width, 159)
            self.assertEqual(im.height, 203)
            self.assertEqual(im.bands, 3)

        self.file_loader("magickload", self.gif_file, gif_valid)
        self.buffer_loader("magickload_buffer", self.gif_file, gif_valid)

    def test_webp(self):
        if not Vips.type_find("VipsForeign", "webpload"):
            print("no webp support in this vips, skipping test")
            return

        def webp_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [71, 166, 236])
            self.assertEqual(im.width, 550)
            self.assertEqual(im.height, 368)
            self.assertEqual(im.bands, 3)

        self.file_loader("webpload", self.webp_file, webp_valid)
        self.buffer_loader("webpload_buffer", self.webp_file, webp_valid)
        self.save_load("%s.webp", self.colour)

    def test_analyzeload(self):
        def analyze_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqual(a[0], 3335)
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 8064)
            self.assertEqual(im.bands, 1)

        self.file_loader("analyzeload", self.analyze_file, analyze_valid)

    def test_matload(self):
        if not Vips.type_find("VipsForeign", "matload"):
            print("no matlab support in this vips, skipping test")
            return

        def matlab_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("matload", self.matlab_file, matlab_valid)

    def test_openexrload(self):
        if not Vips.type_find("VipsForeign", "openexrload"):
            print("no openexr support in this vips, skipping test")
            return

        def exr_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [0.124512, 0.159668, 
                                              0.040375, 1.0], 
                                          places = 5)
            self.assertEqual(im.width, 610)
            self.assertEqual(im.height, 406)
            self.assertEqual(im.bands, 4)

        self.file_loader("openexrload", self.exr_file, exr_valid)

    def test_fitsload(self):
        if not Vips.type_find("VipsForeign", "fitsload"):
            print("no fits support in this vips, skipping test")
            return

        def fits_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [-0.165013, -0.148553, 1.09122,
                                              -0.942242], 
                                          places = 5)
            self.assertEqual(im.width, 200)
            self.assertEqual(im.height, 200)
            self.assertEqual(im.bands, 4)

        self.file_loader("fitsload", self.fits_file, fits_valid)
        self.save_load("%s.fits", self.mono)

    def test_openslideload(self):
        if not Vips.type_find("VipsForeign", "openslideload"):
            print("no openslide support in this vips, skipping test")
            return

        def openslide_valid(self, im):
            a = im.getpoint(10, 10)
            self.assertAlmostEqualObjects(a, [244, 250, 243, 255])
            self.assertEqual(im.width, 2220)
            self.assertEqual(im.height, 2967)
            self.assertEqual(im.bands, 4)

        self.file_loader("openslideload", self.openslide_file, openslide_valid)

    def test_csv(self):
        self.save_load("%s.csv", self.mono)

    def test_matrix(self):
        self.save_load("%s.mat", self.mono)

    def test_ppm(self):
        self.save_load("%s.ppm", self.mono)
        self.save_load("%s.ppm", self.colour)

    def test_rad(self):
        self.save_load("%s.hdr", self.colour)

if __name__ == '__main__':
    unittest.main()

