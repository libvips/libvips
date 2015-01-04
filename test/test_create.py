#!/usr/bin/python

import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 

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
        #print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_black(self):
        im = Vips.Image.black(100, 100)

        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 100)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.bands, 1)
        for i in range (0, 100):
            pixel = im.getpoint(i, i)
            self.assertEqual(len(pixel), 1)
            self.assertEqual(pixel[0], 0)

        im = Vips.Image.black(100, 100, bands = 3)

        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 100)
        self.assertEqual(im.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im.bands, 3)
        for i in range (0, 100):
            pixel = im.getpoint(i, i)
            self.assertEqual(len(pixel), 3)
            self.assertAlmostEqualObjects(pixel, [0, 0, 0])

    def test_buildlut(self):
        M = Vips.Image.new_from_array([[0, 0], 
                                       [255, 100]])
        lut = M.buildlut()
        self.assertEqual(lut.width, 256)
        self.assertEqual(lut.height, 1)
        self.assertEqual(lut.bands, 1)
        p = lut.getpoint(0, 0)
        self.assertEqual(p[0], 0.0)
        p = lut.getpoint(255, 0)
        self.assertEqual(p[0], 100.0)
        p = lut.getpoint(10, 0)
        self.assertEqual(p[0], 100 * 10.0 / 255.0)

if __name__ == '__main__':
    unittest.main()
