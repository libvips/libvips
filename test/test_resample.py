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

class TestResample(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_affine(self):
        im = Vips.Image.new_from_file("images/IMG_4618.jpg")

        # vsqbs is non-interpolatory, don't test this way
        for name in ["nearest", "bicubic", "bilinear", "nohalo", "lbb"]:
            x = im
            interpolate = Vips.Interpolate.new(name)
            for i in range(4):
                # 90 degree rotate
                x = x.affine([0, -1, 1, 0], interpolate = interpolate)
 
            self.assertEqual((x - im).abs().max(), 0)

    def test_resize(self):
        im = Vips.Image.new_from_file("images/IMG_4618.jpg")
        im2 = im.resize(0.25)
        self.assertEqual(im2.width, im.width // 4)
        self.assertEqual(im2.height, im.height // 4)

    def test_shrink(self):
        im = Vips.Image.new_from_file("images/IMG_4618.jpg")
        im2 = im.shrink(4, 4)
        self.assertEqual(im2.width, im.width // 4)
        self.assertEqual(im2.height, im.height // 4)

    def test_similarity(self):
        im = Vips.Image.new_from_file("images/IMG_4618.jpg")
        im2 = im.similarity(angle = 90)
        im3 = im.affine([0, -1, 1, 0])
        # rounding in calculating the affine transform from the angle stops this
        # being exactly true
        self.assertTrue((im2 - im3).abs().max() < 50)

    def test_similarity_scale(self):
        im = Vips.Image.new_from_file("images/IMG_4618.jpg")
        im2 = im.similarity(scale = 2)
        im3 = im.affine([2, 0, 0, 2])
        im2.write_to_file("im2.v")
        im3.write_to_file("im3.v")
        self.assertEqual((im2 - im3).abs().max(), 0)

if __name__ == '__main__':
    unittest.main()
