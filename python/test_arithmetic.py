#!/usr/bin/python

import unittest

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

formats = [Vips.BandFormat.UCHAR, 
           Vips.BandFormat.CHAR, 
           Vips.BandFormat.USHORT, 
           Vips.BandFormat.SHORT, 
           Vips.BandFormat.UINT, 
           Vips.BandFormat.INT, 
           Vips.BandFormat.FLOAT, 
           Vips.BandFormat.DOUBLE, 
           Vips.BandFormat.COMPLEX, 
           Vips.BandFormat.DPCOMPLEX] 

class TestArithmetic(unittest.TestCase):
    def setUp(self):
        black = Vips.Image.black(100, 100)
        mono = black.draw_circle(128, 50, 50, 50)
        colour = Vips.Image.bandjoin([black, mono, black])
        images = [black, mono, colour]

        self.test_set = [x.cast(y) for x in images for y in formats]
        self.avgs = [x.avg() for x in self.test_set]

    def test_addconst(self):
        def add12(x):
            return x + 12

        self.assertEqual([add12(x).avg for x in self.test_set], 
                         [add12(x) for x in self.avgs])

if __name__ == '__main__':
    unittest.main()

