#!/usr/bin/python

import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

Vips.leak_set(True)

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

class TestCreate(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_black(self):
        im = Vips.Image.black(100, 100)

        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 100)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.bands, 1)
        for i in range (0, 100):
            pixel = im(i, i)
            self.assertEqual(len(pixel), 1)
            self.assertEqual(pixel[0], 0)

        im = Vips.Image.black(100, 100, bands = 3)

        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 100)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.bands, 3)
        for i in range (0, 100):
            pixel = im(i, i)
            self.assertEqual(len(pixel), 3)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])

    def test_buildlut(self):
        M = Vips.Image.new_from_array([[0, 0], 
                                       [255, 100]])
        lut = M.buildlut()
        self.assertEqual(lut.width, 256)
        self.assertEqual(lut.height, 1)
        self.assertEqual(lut.bands, 1)
        p = lut(0, 0)
        self.assertEqual(p[0], 0.0)
        p = lut(255, 0)
        self.assertEqual(p[0], 100.0)
        p = lut(10, 0)
        self.assertEqual(p[0], 100 * 10.0 / 255.0)

        M = Vips.Image.new_from_array([[0, 0, 100], 
                                       [255, 100, 0],
                                       [128, 10, 90]])
        lut = M.buildlut()
        self.assertEqual(lut.width, 256)
        self.assertEqual(lut.height, 1)
        self.assertEqual(lut.bands, 2)
        p = lut(0, 0)
        self.assertAlmostEqualObjects(p, [0.0, 100.0])
        p = lut(64, 0)
        self.assertAlmostEqualObjects(p, [5.0, 95.0])

    def test_eye(self):
        im = Vips.Image.eye(100, 90)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertEqual(im.max(), 1.0)
        self.assertEqual(im.min(), -1.0)

        im = Vips.Image.eye(100, 90, uchar = True)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.max(), 255.0)
        self.assertEqual(im.min(), 0.0)

    def test_fractsurf(self):
        im = Vips.Image.fractsurf(100, 90, 2.5)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

    def test_gaussmat(self):
        im = Vips.Image.gaussmat(1, 0.1)
        self.assertEqual(im.width, 5)
        self.assertEqual(im.height, 5)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.DOUBLE)
        self.assertEqual(im.max(), 20)
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        self.assertEqual(total, scale)
        p = im(im.width / 2, im.height / 2)
        self.assertEqual(p[0], 20.0)

        im = Vips.Image.gaussmat(1, 0.1, 
                                 separable = True, precision = "float")
        self.assertEqual(im.width, 5)
        self.assertEqual(im.height, 1)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.DOUBLE)
        self.assertEqual(im.max(), 1.0)
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        self.assertEqual(total, scale)
        p = im(im.width / 2, im.height / 2)
        self.assertEqual(p[0], 1.0)

    def test_gaussnoise(self):
        im = Vips.Image.gaussnoise(100, 90)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

        im = Vips.Image.gaussnoise(100, 90, sigma = 10, mean = 100)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

        sigma = im.deviate()
        mean = im.avg()

        self.assertAlmostEqual(sigma, 10, places = 0)
        self.assertAlmostEqual(mean, 100, places = 0)

    def test_grey(self):
        im = Vips.Image.grey(100, 90)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

        p = im(0, 0)
        self.assertEqual(p[0], 0.0)
        p = im(99, 0)
        self.assertEqual(p[0], 1.0)
        p = im(0, 89)
        self.assertEqual(p[0], 0.0)
        p = im(99, 89)
        self.assertEqual(p[0], 1.0)

        im = Vips.Image.grey(100, 90, uchar = True)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 90)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)

        p = im(0, 0)
        self.assertEqual(p[0], 0)
        p = im(99, 0)
        self.assertEqual(p[0], 255)
        p = im(0, 89)
        self.assertEqual(p[0], 0)
        p = im(99, 89)
        self.assertEqual(p[0], 255)

    def test_identity(self):
        im = Vips.Image.identity()
        self.assertEqual(im.width, 256)
        self.assertEqual(im.height, 1)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)

        p = im(0, 0)
        self.assertEqual(p[0], 0.0)
        p = im(255, 0)
        self.assertEqual(p[0], 255.0)
        p = im(128, 0)
        self.assertEqual(p[0], 128.0)

        im = Vips.Image.identity(ushort = True)
        self.assertEqual(im.width, 65536)
        self.assertEqual(im.height, 1)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.USHORT)

        p = im(0, 0)
        self.assertEqual(p[0], 0)
        p = im(99, 0)
        self.assertEqual(p[0], 99)
        p = im(65535, 0)
        self.assertEqual(p[0], 65535)

    def test_invertlut(self):
        lut = Vips.Image.new_from_array([[0.1, 0.2, 0.3, 0.1], 
                                         [0.2, 0.4, 0.4, 0.2], 
                                         [0.7, 0.5, 0.6, 0.3]])
        im = lut.invertlut()
        self.assertEqual(im.width, 256)
        self.assertEqual(im.height, 1)
        self.assertEqual(im.bands, 3)
        self.assertEqual(im.format, Vips.BandFormat.DOUBLE)

        p = im(0, 0)
        self.assertAlmostEqualObjects(p, [0, 0, 0])
        p = im(255, 0)
        self.assertAlmostEqualObjects(p, [1, 1, 1])
        p = im(0.2 * 255, 0)
        self.assertAlmostEqual(p[0], 0.1, places = 2)
        p = im(0.3 * 255, 0)
        self.assertAlmostEqual(p[1], 0.1, places = 2)
        p = im(0.1 * 255, 0)
        self.assertAlmostEqual(p[2], 0.1, places = 2)

    def test_logmat(self):
        im = Vips.Image.logmat(1, 0.1)
        self.assertEqual(im.width, 7)
        self.assertEqual(im.height, 7)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.DOUBLE)
        self.assertEqual(im.max(), 20)
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        self.assertEqual(total, scale)
        p = im(im.width / 2, im.height / 2)
        self.assertEqual(p[0], 20.0)

        im = Vips.Image.logmat(1, 0.1, 
                               separable = True, precision = "float")
        self.assertEqual(im.width, 7)
        self.assertEqual(im.height, 1)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.DOUBLE)
        self.assertEqual(im.max(), 1.0)
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        self.assertEqual(total, scale)
        p = im(im.width / 2, im.height / 2)
        self.assertEqual(p[0], 1.0)

    def test_mask_butterworth_band(self):
        im = Vips.Image.mask_butterworth_band(128, 128, 2, 0.5, 0.5, 0.7, 0.1)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.max(), 1, places = 2)
        p = im(32, 32)
        self.assertEqual(p[0], 1.0)

        im = Vips.Image.mask_butterworth_band(128, 128, 2, 0.5, 0.5, 0.7, 0.1,
                                             uchar = True, optical = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.max(), 255)
        p = im(32, 32)
        self.assertEqual(p[0], 255.0)
        p = im(64, 64)
        self.assertEqual(p[0], 255.0)

        im = Vips.Image.mask_butterworth_band(128, 128, 2, 0.5, 0.5, 0.7, 0.1,
                                             uchar = True, optical = True, 
                                             nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.max(), 255)
        p = im(32, 32)
        self.assertEqual(p[0], 255.0)
        p = im(64, 64)
        self.assertNotEqual(p[0], 255)

    def test_mask_butterworth(self):
        im = Vips.Image.mask_butterworth(128, 128, 2, 0.7, 0.1, 
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.min(), 0, places = 2)
        p = im(0, 0)
        self.assertEqual(p[0], 0.0)
        v, x, y = im.maxpos()
        self.assertEqual(x, 64)
        self.assertEqual(y, 64)

        im = Vips.Image.mask_butterworth(128, 128, 2, 0.7, 0.1, 
                                         optical = True, uchar = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertAlmostEqual(im.min(), 0, places = 2)
        p = im(64, 64)
        self.assertEqual(p[0], 255)

    def test_mask_butterworth_ring(self):
        im = Vips.Image.mask_butterworth_ring(128, 128, 2, 0.7, 0.1, 0.5,
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        p = im(45, 0)
        self.assertAlmostEqual(p[0], 1.0, places = 4)
        v, x, y = im.minpos()
        self.assertEqual(x, 64)
        self.assertEqual(y, 64)

    def test_mask_fractal(self):
        im = Vips.Image.mask_fractal(128, 128, 2.3)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

    def test_mask_gaussian_band(self):
        im = Vips.Image.mask_gaussian_band(128, 128, 0.5, 0.5, 0.7, 0.1)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.max(), 1, places = 2)
        p = im(32, 32)
        self.assertEqual(p[0], 1.0)

    def test_mask_gaussian(self):
        im = Vips.Image.mask_gaussian(128, 128, 0.7, 0.1, 
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.min(), 0, places = 2)
        p = im(0, 0)
        self.assertEqual(p[0], 0.0)

    def test_mask_gaussian_ring(self):
        im = Vips.Image.mask_gaussian_ring(128, 128, 0.7, 0.1, 0.5,
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        p = im(45, 0)
        self.assertAlmostEqual(p[0], 1.0, places = 3)

    def test_mask_ideal_band(self):
        im = Vips.Image.mask_ideal_band(128, 128, 0.5, 0.5, 0.7)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.max(), 1, places = 2)
        p = im(32, 32)
        self.assertEqual(p[0], 1.0)

    def test_mask_ideal(self):
        im = Vips.Image.mask_ideal(128, 128, 0.7, 
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        self.assertAlmostEqual(im.min(), 0, places = 2)
        p = im(0, 0)
        self.assertEqual(p[0], 0.0)

    def test_mask_gaussian_ring(self):
        im = Vips.Image.mask_ideal_ring(128, 128, 0.7, 0.5,
                                         nodc = True)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)
        p = im(45, 0)
        self.assertAlmostEqual(p[0], 1.0, places = 3)

    def test_sines(self):
        im = Vips.Image.sines(128, 128)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

    def test_text(self):
        im = Vips.Image.text("Hello, world!")
        self.assertTrue(im.width > 10)
        self.assertTrue(im.height > 10)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.max(), 255)
        self.assertEqual(im.min(), 0)

    def test_tonelut(self):
        im = Vips.Image.tonelut()
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.USHORT)
        self.assertEqual(im.width, 32768)
        self.assertEqual(im.height, 1)
        self.assertTrue(im.hist_ismonotonic())

    def test_xyz(self):
        im = Vips.Image.xyz(128, 128)
        self.assertEqual(im.bands, 2)
        self.assertEqual(im.format, Vips.BandFormat.UINT)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        p = im(45, 35)
        self.assertAlmostEqualObjects(p, [45, 35])

    def test_zone(self):
        im = Vips.Image.zone(128, 128)
        self.assertEqual(im.width, 128)
        self.assertEqual(im.height, 128)
        self.assertEqual(im.bands, 1)
        self.assertEqual(im.format, Vips.BandFormat.FLOAT)

if __name__ == '__main__':
    unittest.main()
