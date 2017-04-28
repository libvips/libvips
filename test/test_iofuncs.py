#!/usr/bin/python3

from __future__ import division
import unittest
import math

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

class TestIofuncs(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertEqualObjects(self, a, b, msg = ''):
        #print('assertEqualObjects %s = %s' % (a, b))
        for x, y in zip_expand(a, b):
            self.assertEqual(x, y, msg = msg)

    # test the vips7 filename splitter ... this is very fragile and annoying
    # code with lots of cases
    def test_split7(self):
        def split(path):
            filename7 = Vips.path_filename7(path)
            mode7 = Vips.path_mode7(path)

            return [filename7, mode7]

        cases = [
            ["c:\\silly:dir:name\\fr:ed.tif:jpeg:95,,,,c:\\icc\\srgb.icc",
                ["c:\\silly:dir:name\\fr:ed.tif", 
                 "jpeg:95,,,,c:\\icc\\srgb.icc"]],
            ["I180:",
                ["I180",
                 ""]],
            ["c:\\silly:",
                ["c:\\silly",
                 ""]],
            ["c:\\program files\\x:hello",
                ["c:\\program files\\x",
                 "hello"]],
            ["C:\\fixtures\\2569067123_aca715a2ee_o.jpg",
                ["C:\\fixtures\\2569067123_aca715a2ee_o.jpg",
                 ""]]
        ]
            
        for case in cases:
            self.assertEqualObjects(split(case[0]), case[1])

    def test_new_from_image(self):
        im = Vips.Image.mask_ideal(100, 100, 0.5, reject = True, optical = True)

        im2 = im.new_from_image(12)

        self.assertEqual(im2.width, im.width)
        self.assertEqual(im2.height, im.height)
        self.assertEqual(im2.interpretation, im.interpretation)
        self.assertEqual(im2.format, im.format)
        self.assertEqual(im2.xres, im.xres)
        self.assertEqual(im2.yres, im.yres)
        self.assertEqual(im2.xoffset, im.xoffset)
        self.assertEqual(im2.yoffset, im.yoffset)
        self.assertEqual(im2.bands, 1)
        self.assertEqual(im2.avg(), 12)

        im2 = im.new_from_image([1,2,3])

        self.assertEqual(im2.bands, 3)
        self.assertEqual(im2.avg(), 2)


if __name__ == '__main__':
    unittest.main()
