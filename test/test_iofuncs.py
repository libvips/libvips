#!/usr/bin/python3

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

if __name__ == '__main__':
    unittest.main()
