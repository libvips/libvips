#!/usr/bin/python

import sys

from gi.repository import Vips 
from vips8 import vips

im = Vips.Image.new_from_file(sys.argv[1])

im = im.crop(100, 100, im.width - 200, im.height - 200)

im = im.affine([0.9, 0, 0, 0.9])

mask = Vips.Image.new_from_array([[-1, -1,  -1], 
                                  [-1,  16, -1], 
                                  [-1, -1,  -1]], scale = 8)
im = im.conv(mask)

im.write_to_file(sys.argv[2])
