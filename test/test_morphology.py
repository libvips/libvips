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

class TestMorphology(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def test_countlines(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_line(255, 0, 50, 100, 50)
        n_lines = im.countlines(Vips.Direction.HORIZONTAL)
        self.assertEqual(n_lines, 1)

    def test_labelregions(self):
        im = Vips.Image.black(100, 100)
        im = im.draw_circle(255, 50, 50, 25, fill = True)
        mask, opts = im.labelregions(segments = True)

        self.assertEqual(opts['segments'], 3)
        self.assertEqual(mask.max(), 2)

if __name__ == '__main__':
    unittest.main()
