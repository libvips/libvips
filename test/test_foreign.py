#!/usr/bin/python

from __future__ import division
import unittest
import math
import os
import shutil
from tempfile import NamedTemporaryFile

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
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
        self.pdf_file = "images/ISO_12233-reschart.pdf"
        self.cmyk_pdf_file = "images/cmyktest.pdf"
        self.svg_file = "images/vips-profile.svg"
        self.svgz_file = "images/vips-profile.svgz"

        self.colour = Vips.Image.jpegload(self.jpeg_file)
        self.mono = self.colour.extract_band(1)
        self.rad = self.colour.float2rad()
        self.cmyk = self.colour.bandjoin(self.mono)
        self.cmyk = self.cmyk.copy(interpretation = Vips.Interpretation.CMYK)

        im = Vips.Image.new_from_file(self.gif_file)
        self.onebit = im > 128

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

    def save_load_file(self, filename, options, im, thresh):
        # yuk! 
        # but we can't set format parameters for Vips.Image.new_temp_file()
        im.write_to_file(filename + options)
        x = Vips.Image.new_from_file(filename)

        self.assertEqual(im.width, x.width)
        self.assertEqual(im.height, x.height)
        self.assertEqual(im.bands, x.bands)
        max_diff = (im - x).abs().max()
        self.assertTrue(max_diff <= thresh)
        x = None
        os.unlink(filename)

    def save_load_buffer(self, saver, loader, im, max_diff = 0):
        buf = Vips.call(saver, im)
        x = Vips.call(loader, buf)

        self.assertEqual(im.width, x.width)
        self.assertEqual(im.height, x.height)
        self.assertEqual(im.bands, x.bands)
        self.assertLessEqual((im - x).abs().max(), max_diff)

    def save_buffer_tempfile(self, saver, suf, im, max_diff = 0):
        buf = Vips.call(saver, im)
        f = NamedTemporaryFile(suffix=suf, delete=False)
        f.write(buf)
        f.close()
        x = Vips.Image.new_from_file(f.name)

        self.assertEqual(im.width, x.width)
        self.assertEqual(im.height, x.height)
        self.assertEqual(im.bands, x.bands)
        self.assertLessEqual((im - x).abs().max(), max_diff)

        os.unlink(f.name)

    def test_vips(self):
        self.save_load_file("test.v", "", self.colour, 0)

        # check we can save and restore metadata
        self.colour.write_to_file("test.v")
        x = Vips.Image.new_from_file("test.v")
        before_exif = self.colour.get_value("exif-data")
        after_exif = x.get_value("exif-data")

        self.assertEqual(len(before_exif), len(after_exif))
        for i in range(len(before_exif)):
            self.assertEqual(before_exif[i], after_exif[i])

        x = None
        os.unlink("test.v")

    def test_jpeg(self):
        x = Vips.type_find("VipsForeign", "jpegload")
        if not x.is_instantiatable():
            print("no jpeg support in this vips, skipping test")
            return

        def jpeg_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [6, 5, 3])
            profile = im.get_value("icc-profile-data")
            self.assertEqual(len(profile), 1352)
            self.assertEqual(im.width, 1024)
            self.assertEqual(im.height, 768)
            self.assertEqual(im.bands, 3)

        self.file_loader("jpegload", self.jpeg_file, jpeg_valid)
        self.buffer_loader("jpegload_buffer", self.jpeg_file, jpeg_valid)
        self.save_load_buffer("jpegsave_buffer", "jpegload_buffer", self.colour,
                             60)
        self.save_load("%s.jpg", self.mono)
        self.save_load("%s.jpg", self.colour)

        # see if we have exif parsing
        have_exif = False
        x = Vips.Image.new_from_file(self.jpeg_file)
        try:
            # our test image has this field
            y = x.get_value("exif-ifd0-Orientation")
            have_exif = True
        except:
            pass

        if have_exif:
            # we need a copy of the image to set the new metadata on
            # otherwise we get caching problems
            x = Vips.Image.new_from_file(self.jpeg_file)
            x = x.copy()
            x.set_value("orientation", 2)
            x.write_to_file("test.jpg")
            x = Vips.Image.new_from_file("test.jpg")
            y = x.get_value("orientation")
            self.assertEqual(y, 2)
            os.unlink("test.jpg")

            x = Vips.Image.new_from_file(self.jpeg_file)
            x = x.copy()
            x.set_value("orientation", 2)
            x.write_to_file("test-12.jpg")

            x = Vips.Image.new_from_file("test-12.jpg")
            y = x.get_value("orientation")
            self.assertEqual(y, 2)
            x.remove("orientation")
            x.write_to_file("test-13.jpg")
            x = Vips.Image.new_from_file("test-13.jpg")
            y = x.get_value("orientation")
            self.assertEqual(y, 1)
            os.unlink("test-12.jpg")
            os.unlink("test-13.jpg")

            x = Vips.Image.new_from_file(self.jpeg_file)
            x = x.copy()
            x.set_value("orientation", 6)
            x.write_to_file("test-14.jpg")

            x1 = Vips.Image.new_from_file("test-14.jpg")
            x2 = Vips.Image.new_from_file("test-14.jpg", autorotate = True)
            self.assertEqual(x1.width, x2.height)
            self.assertEqual(x1.height, x2.width)
            os.unlink("test-14.jpg")

    def test_png(self):
        x = Vips.type_find("VipsForeign", "pngload")
        if not x.is_instantiatable():
            print("no png support in this vips, skipping test")
            return

        def png_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("pngload", self.png_file, png_valid)
        self.buffer_loader("pngload_buffer", self.png_file, png_valid)
        self.save_load_buffer("pngsave_buffer", "pngload_buffer", self.colour)
        self.save_load("%s.png", self.mono)
        self.save_load("%s.png", self.colour)

    def test_tiff(self):
        x = Vips.type_find("VipsForeign", "tiffload")
        if not x.is_instantiatable():
            print("no tiff support in this vips, skipping test")
            return

        def tiff_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("tiffload", self.tiff_file, tiff_valid)
        self.buffer_loader("tiffload_buffer", self.tiff_file, tiff_valid)
        self.save_load("%s.tif", self.mono)
        self.save_load("%s.tif", self.colour)
        self.save_load("%s.tif", self.cmyk)

        self.save_load("%s.tif", self.onebit)
        self.save_load_file("test-1.tif", "[squash]", self.onebit, 0)
        self.save_load_file("test-2.tif", "[miniswhite]", self.onebit, 0)
        self.save_load_file("test-3.tif", "[squash,miniswhite]", self.onebit, 0)

        self.save_load_file("test-4.tif",
                            "[profile=images/sRGB.icm]",
                            self.colour, 0)
        self.save_load_file("test-5.tif", "[tile]", self.colour, 0)
        self.save_load_file("test-6.tif", "[tile,pyramid]", self.colour, 0)
        self.save_load_file("test-7.tif", 
                            "[tile,pyramid,compression=jpeg]", self.colour, 60)
        self.save_load_file("test-8.tif", "[bigtiff]", self.colour, 0)
        self.save_load_file("test-9.tif", "[compression=jpeg]", self.colour, 60)
        self.save_load_file("test-10.tif", 
                            "[tile,tile-width=256]", self.colour, 10)

        # we need a copy of the image to set the new metadata on
        # otherwise we get caching problems
        x = Vips.Image.new_from_file(self.tiff_file)
        x = x.copy()
        x.set_value("orientation", 2)
        x.write_to_file("test-11.tif")
        x = Vips.Image.new_from_file("test-11.tif")
        y = x.get_value("orientation")
        self.assertEqual(y, 2)
        os.unlink("test-11.tif")

        # we need a copy of the image to set the new metadata on
        # otherwise we get caching problems
        x = Vips.Image.new_from_file(self.tiff_file)
        x = x.copy()
        x.set_value("orientation", 2)
        x.write_to_file("test-12.tif")

        x = Vips.Image.new_from_file("test-12.tif")
        y = x.get_value("orientation")
        self.assertEqual(y, 2)
        x.remove("orientation")
        x.write_to_file("test-13.tif")
        x = Vips.Image.new_from_file("test-13.tif")
        y = x.get_value("orientation")
        self.assertEqual(y, 1)
        os.unlink("test-12.tif")
        os.unlink("test-13.tif")

        x = Vips.Image.new_from_file(self.tiff_file)
        x = x.copy()
        x.set_value("orientation", 6)
        x.write_to_file("test-14.tif")

        x1 = Vips.Image.new_from_file("test-14.tif")
        x2 = Vips.Image.new_from_file("test-14.tif", autorotate = True)
        self.assertEqual(x1.width, x2.height)
        self.assertEqual(x1.height, x2.width)
        os.unlink("test-14.tif")

    def test_magickload(self):
        x = Vips.type_find("VipsForeign", "magickload")
        if not x.is_instantiatable():
            print("no magick support in this vips, skipping test")
            return

        def gif_valid(self, im):
            a = im(10, 10)
            # some libMagick produce an RGB for this image, some a mono, some
            # rgba :-( 
            if len(a) == 4:
                self.assertAlmostEqual(a, [33, 33, 33, 255])
            elif len(a) == 3:
                self.assertAlmostEqual(a, [33, 33, 33])
            else:
                self.assertAlmostEqual(a, [33])

            self.assertEqual(im.bands, len(a))
            self.assertEqual(im.width, 159)
            self.assertEqual(im.height, 203)

        self.file_loader("magickload", self.gif_file, gif_valid)
        self.buffer_loader("magickload_buffer", self.gif_file, gif_valid)

    def test_webp(self):
        x = Vips.type_find("VipsForeign", "webpload")
        if not x.is_instantiatable():
            print("no webp support in this vips, skipping test")
            return

        def webp_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [71, 166, 236])
            self.assertEqual(im.width, 550)
            self.assertEqual(im.height, 368)
            self.assertEqual(im.bands, 3)

        self.file_loader("webpload", self.webp_file, webp_valid)
        self.buffer_loader("webpload_buffer", self.webp_file, webp_valid)
        self.save_load_buffer("webpsave_buffer", "webpload_buffer", self.colour,
                             50)
        self.save_load("%s.webp", self.colour)

        # test lossless mode
        im = Vips.Image.new_from_file(self.webp_file)
        buf = im.webpsave_buffer(lossless = True)
        im2 = Vips.Image.new_from_buffer(buf, "")
        self.assertEqual(im.avg(), im2.avg())

        # higher Q should mean a bigger buffer
        b1 = im.webpsave_buffer(Q = 10)
        b2 = im.webpsave_buffer(Q = 90)
        self.assertGreater(len(b2), len(b1))

    def test_analyzeload(self):
        x = Vips.type_find("VipsForeign", "analyzeload")
        if not x.is_instantiatable():
            print("no analyze support in this vips, skipping test")
            return

        def analyze_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqual(a[0], 3335)
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 8064)
            self.assertEqual(im.bands, 1)

        self.file_loader("analyzeload", self.analyze_file, analyze_valid)

    def test_matload(self):
        x = Vips.type_find("VipsForeign", "matload")
        if not x.is_instantiatable():
            print("no matlab support in this vips, skipping test")
            return

        def matlab_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [38671.0, 33914.0, 26762.0])
            self.assertEqual(im.width, 290)
            self.assertEqual(im.height, 442)
            self.assertEqual(im.bands, 3)

        self.file_loader("matload", self.matlab_file, matlab_valid)

    def test_openexrload(self):
        x = Vips.type_find("VipsForeign", "openexrload")
        if not x.is_instantiatable():
            print("no openexr support in this vips, skipping test")
            return

        def exr_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [0.124512, 0.159668, 
                                              0.040375, 1.0], 
                                          places = 5)
            self.assertEqual(im.width, 610)
            self.assertEqual(im.height, 406)
            self.assertEqual(im.bands, 4)

        self.file_loader("openexrload", self.exr_file, exr_valid)

    def test_fitsload(self):
        x = Vips.type_find("VipsForeign", "fitsload")
        if not x.is_instantiatable():
            print("no fits support in this vips, skipping test")
            return

        def fits_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [-0.165013, -0.148553, 1.09122,
                                              -0.942242], 
                                          places = 5)
            self.assertEqual(im.width, 200)
            self.assertEqual(im.height, 200)
            self.assertEqual(im.bands, 4)

        self.file_loader("fitsload", self.fits_file, fits_valid)
        self.save_load("%s.fits", self.mono)

    def test_openslideload(self):
        x = Vips.type_find("VipsForeign", "openslideload")
        if not x.is_instantiatable():
            print("no openslide support in this vips, skipping test")
            return

        def openslide_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [244, 250, 243, 255])
            self.assertEqual(im.width, 2220)
            self.assertEqual(im.height, 2967)
            self.assertEqual(im.bands, 4)

        self.file_loader("openslideload", self.openslide_file, openslide_valid)

    def test_pdfload(self):
        x = Vips.type_find("VipsForeign", "pdfload")
        if not x.is_instantiatable():
            print("no pdf support in this vips, skipping test")
            return

        def pdf_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [35, 31, 32, 255])
            self.assertEqual(im.width, 1133)
            self.assertEqual(im.height, 680)
            self.assertEqual(im.bands, 4)

        self.file_loader("pdfload", self.pdf_file, pdf_valid)
        self.buffer_loader("pdfload_buffer", self.pdf_file, pdf_valid)

        im = Vips.Image.new_from_file(self.pdf_file)
        x = Vips.Image.new_from_file(self.pdf_file, scale = 2)
        self.assertLess(abs(im.width * 2 - x.width), 2)
        self.assertLess(abs(im.height * 2 - x.height), 2)

        im = Vips.Image.new_from_file(self.pdf_file)
        x = Vips.Image.new_from_file(self.pdf_file, dpi = 144)
        self.assertLess(abs(im.width * 2 - x.width), 2)
        self.assertLess(abs(im.height * 2 - x.height), 2)

    def test_gifload(self):
        x = Vips.type_find("VipsForeign", "gifload")
        if not x.is_instantiatable():
            print("no gif support in this vips, skipping test")
            return

        def gif_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [33])
            self.assertEqual(im.width, 159)
            self.assertEqual(im.height, 203)
            self.assertEqual(im.bands, 1)

        self.file_loader("gifload", self.gif_file, gif_valid)
        self.buffer_loader("gifload_buffer", self.gif_file, gif_valid)

    def test_svgload(self):
        x = Vips.type_find("VipsForeign", "svgload")
        if not x.is_instantiatable():
            print("no svg support in this vips, skipping test")
            return

        def svg_valid(self, im):
            a = im(10, 10)
            self.assertAlmostEqualObjects(a, [0, 0, 77, 255])
            self.assertEqual(im.width, 360)
            self.assertEqual(im.height, 588)
            self.assertEqual(im.bands, 4)

        self.file_loader("svgload", self.svg_file, svg_valid)
        self.buffer_loader("svgload_buffer", self.svg_file, svg_valid)

        self.file_loader("svgload", self.svgz_file, svg_valid)
        self.buffer_loader("svgload_buffer", self.svgz_file, svg_valid)

        im = Vips.Image.new_from_file(self.svg_file)
        x = Vips.Image.new_from_file(self.svg_file, scale = 2)
        self.assertLess(abs(im.width * 2 - x.width), 2)
        self.assertLess(abs(im.height * 2 - x.height), 2)

        im = Vips.Image.new_from_file(self.svg_file)
        x = Vips.Image.new_from_file(self.svg_file, dpi = 144)
        self.assertLess(abs(im.width * 2 - x.width), 2)
        self.assertLess(abs(im.height * 2 - x.height), 2)

    def test_csv(self):
        self.save_load("%s.csv", self.mono)

    def test_matrix(self):
        self.save_load("%s.mat", self.mono)

    def test_ppm(self):
        x = Vips.type_find("VipsForeign", "ppmload")
        if not x.is_instantiatable():
            print("no PPM support in this vips, skipping test")
            return

        self.save_load("%s.ppm", self.mono)
        self.save_load("%s.ppm", self.colour)

    def test_rad(self):
        x = Vips.type_find("VipsForeign", "radload")
        if not x.is_instantiatable():
            print("no Radiance support in this vips, skipping test")
            return

        self.save_load("%s.hdr", self.colour)
        self.save_buffer_tempfile("radsave_buffer", ".hdr", self.rad, max_diff = 0)

    def test_dzsave(self):
        x = Vips.type_find("VipsForeign", "dzsave")
        if not x.is_instantiatable():
            print("no dzsave support in this vips, skipping test")
            return

        # dzsave is hard to test, there are so many options
        # test each option separately and hope they all function together
        # correctly

        # default deepzoom layout ... we must use png here, since we want to
        # test the overlap for equality
        self.colour.dzsave("test", suffix = ".png")

        # tes horizontal overlap ... expect 256 step, overlap 1 
        x = Vips.Image.new_from_file("test_files/10/0_0.png")
        self.assertEqual(x.width, 255)
        y = Vips.Image.new_from_file("test_files/10/1_0.png")
        self.assertEqual(y.width, 256)

        # the right two columns of x should equal the left two columns of y
        left = x.crop(x.width - 2, 0, 2, x.height)
        right = y.crop(0, 0, 2, y.height)
        self.assertEqual((left - right).abs().max(), 0)

        # test vertical overlap
        self.assertEqual(x.height, 255)
        y = Vips.Image.new_from_file("test_files/10/0_1.png")
        self.assertEqual(y.height, 256)

        # the bottom two rows of x should equal the top two rows of y
        top = x.crop(0, x.height - 2, x.width, 2)
        bottom = y.crop(0, 0, y.width, 2)
        self.assertEqual((top - bottom).abs().max(), 0)

        # there should be a bottom layer
        x = Vips.Image.new_from_file("test_files/0/0_0.png")
        self.assertEqual(x.width, 1)
        self.assertEqual(x.height, 1)

        # 10 should be the final layer
        self.assertFalse(os.path.isdir("test_files/11"))

        shutil.rmtree("test_files")
        os.unlink("test.dzi")

        # default google layout
        self.colour.dzsave("test", layout = "google")

        # test bottom-right tile ... default is 256x256 tiles, overlap 0
        x = Vips.Image.new_from_file("test/2/2/3.jpg")
        self.assertEqual(x.width, 256)
        self.assertEqual(x.height, 256)
        self.assertFalse(os.path.exists("test/2/2/4.jpg"))
        self.assertFalse(os.path.exists("test/3"))
        x = Vips.Image.new_from_file("test/blank.png")
        self.assertEqual(x.width, 256)
        self.assertEqual(x.height, 256)

        shutil.rmtree("test")

        # default zoomify layout
        self.colour.dzsave("test", layout = "zoomify")

        # 256x256 tiles, no overlap
        self.assertTrue(os.path.exists("test/ImageProperties.xml"))
        x = Vips.Image.new_from_file("test/TileGroup0/2-3-2.jpg")
        self.assertEqual(x.width, 256)
        self.assertEqual(x.height, 256)

        shutil.rmtree("test")

        # test zip output
        self.colour.dzsave("test.zip")
        self.assertFalse(os.path.exists("test_files"))
        self.assertFalse(os.path.exists("test.dzi"))

        # test compressed zip output
        self.colour.dzsave("test_compressed.zip", compression = -1)
        self.assertLess(os.path.getsize("test_compressed.zip"),
                        os.path.getsize("test.zip"))
        os.unlink("test.zip")
        os.unlink("test_compressed.zip")

        # test suffix 
        self.colour.dzsave("test", suffix = ".png")

        x = Vips.Image.new_from_file("test_files/10/0_0.png")
        self.assertEqual(x.width, 255)

        shutil.rmtree("test_files")
        os.unlink("test.dzi")

        # test overlap
        self.colour.dzsave("test", overlap = 200)

        y = Vips.Image.new_from_file("test_files/10/1_1.jpeg")
        self.assertEqual(y.width, 654)

        shutil.rmtree("test_files")
        os.unlink("test.dzi")

        # test tile-size
        self.colour.dzsave("test", tile_size = 512)

        y = Vips.Image.new_from_file("test_files/10/0_0.jpeg")
        self.assertEqual(y.width, 513)
        self.assertEqual(y.height, 513)

        shutil.rmtree("test_files")
        os.unlink("test.dzi")

if __name__ == '__main__':
    unittest.main()

