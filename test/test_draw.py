#!/usr/bin/python

import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
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

class TestDraw(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_draw_circle(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25)
        pixel = im(25, 50)
        self.assertEqual(len(pixel), 1)
        self.assertEqual(pixel[0], 100)
        pixel = im(26, 50)
        self.assertEqual(len(pixel), 1)
        self.assertEqual(pixel[0], 0)

        im = Vips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25, fill = True)
        pixel = im(25, 50)
        self.assertEqual(len(pixel), 1)
        self.assertEqual(pixel[0], 100)
        pixel = im(26, 50)
        self.assertEqual(pixel[0], 100)
        pixel = im(24, 50)
        self.assertEqual(pixel[0], 0)

    def test_draw_flood(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25)
        im = im.draw_flood(100, 50, 50)

        im2 = Vips.Image.black(100, 100)
        im2 = im.draw_circle(100, 50, 50, 25, fill = True)

        diff = (im - im2).abs().max()
        self.assertEqual(diff, 0)

    def test_draw_image(self):
        im = Vips.Image.black(51, 51)
        im = im.draw_circle(100, 25, 25, 25, fill = True)

        im2 = Vips.Image.black(100, 100)
        im2 = im2.draw_image(im, 25, 25)

        im3 = Vips.Image.black(100, 100)
        im3 = im3.draw_circle(100, 50, 50, 25, fill = True)

        diff = (im2 - im3).abs().max()
        self.assertEqual(diff, 0)

    def test_draw_line(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_line(100, 0, 0, 100, 0)
        pixel = im(0, 0)
        self.assertEqual(len(pixel), 1)
        self.assertEqual(pixel[0], 100)
        pixel = im(0, 1)
        self.assertEqual(len(pixel), 1)
        self.assertEqual(pixel[0], 0)

    def test_draw_mask(self):
        mask = Vips.Image.black(51, 51)
        mask = mask.draw_circle(128, 25, 25, 25, fill = True)

        im = Vips.Image.black(100, 100)
        im = im.draw_mask(200, mask, 25, 25)

        im2 = Vips.Image.black(100, 100)
        im2 = im2.draw_circle(100, 50, 50, 25, fill = True)

        diff = (im - im2).abs().max()
        self.assertEqual(diff, 0)

    def test_draw_rect(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_rect(100, 25, 25, 50, 50, fill = True)

        im2 = Vips.Image.black(100, 100)
        for y in range(25, 75):
            im2 = im2.draw_line(100, 25, y, 74, y)

        diff = (im - im2).abs().max()
        self.assertEqual(diff, 0)

    def test_draw_smudge(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25, fill = True)

        im2 = im.draw_smudge(10, 10, 50, 50)

        im3 = im.crop(10, 10, 50, 50)
        
        im4 = im2.draw_image(im3, 10, 10)

        diff = (im4 - im).abs().max()
        self.assertEqual(diff, 0)

if __name__ == '__main__':
    unittest.main()
