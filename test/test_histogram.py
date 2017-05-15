#!/usr/bin/python
# vim: set fileencoding=utf-8 :

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

class TestHistogram(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_hist_cum(self):
        im = Vips.Image.identity()

        sum = im.avg() * 256

        cum = im.hist_cum()

        p = cum(255, 0)
        self.assertEqual(p[0], sum)

    def test_hist_equal(self):
        im = Vips.Image.new_from_file("images/йцук.jpg")

        im2 = im.hist_equal()

        self.assertEqual(im.width, im2.width)
        self.assertEqual(im.height, im2.height)

        self.assertTrue(im.avg() < im2.avg())
        self.assertTrue(im.deviate() < im2.deviate())

    def test_hist_ismonotonic(self):
        im = Vips.Image.identity()
        self.assertTrue(im.hist_ismonotonic())

    def test_hist_local(self):
        im = Vips.Image.new_from_file("images/йцук.jpg")

        im2 = im.hist_local(10, 10)

        self.assertEqual(im.width, im2.width)
        self.assertEqual(im.height, im2.height)

        self.assertTrue(im.avg() < im2.avg())
        self.assertTrue(im.deviate() < im2.deviate())

        im3 = im.hist_local(10, 10, max_slope = 3)

        self.assertEqual(im.width, im2.width)
        self.assertEqual(im.height, im2.height)

        self.assertTrue(im3.deviate() < im2.deviate())

    def test_hist_match(self):
        im = Vips.Image.identity()
        im2 = Vips.Image.identity()

        matched = im.hist_match(im2)

        self.assertEqual((im - matched).abs().max(), 0.0)

    def test_hist_norm(self):
        im = Vips.Image.identity()
        im2 = im.hist_norm()

        self.assertEqual((im - im2).abs().max(), 0.0)

    def test_hist_plot(self):
        im = Vips.Image.identity()
        im2 = im.hist_plot()

        self.assertEqual(im2.width, 256)
        self.assertEqual(im2.height, 256)
        self.assertEqual(im2.format, Vips.BandFormat.UCHAR)
        self.assertEqual(im2.bands, 1)

    def test_hist_map(self):
        im = Vips.Image.identity()

        im2 = im.maplut(im)

        self.assertEqual((im - im2).abs().max(), 0.0)

    def test_percent(self):
        im = Vips.Image.new_from_file("images/йцук.jpg").extract_band(1)

        pc = im.percent(90)

        msk = im <= pc
        n_set = (msk.avg() * msk.width * msk.height) / 255.0
        pc_set = 100 * n_set / (msk.width * msk.height)

        self.assertAlmostEqual(pc_set, 90, places = 0)

    def test_hist_entropy(self):
        im = Vips.Image.new_from_file("images/йцук.jpg").extract_band(1)

        ent = im.hist_find().hist_entropy()

        self.assertAlmostEqual(ent, 4.37, places = 2)

    def test_stdif(self):
        im = Vips.Image.new_from_file("images/йцук.jpg")

        im2 = im.stdif(10, 10)

        self.assertEqual(im.width, im2.width)
        self.assertEqual(im.height, im2.height)

        # new mean should be closer to target mean
        self.assertTrue(abs(im.avg() - 128) > abs(im2.avg() - 128))

if __name__ == '__main__':
    unittest.main()
