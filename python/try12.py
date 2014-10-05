#!/usr/bin/python

import sys

from gi.repository import Vips 
from vips8 import vips

im = Vips.Image.new_from_file(sys.argv[1], access = Vips.Access.SEQUENTIAL)

black = Vips.Image.black(im.width, 150)
red = (black + [255, 0, 0]).cast(Vips.BandFormat.UCHAR)
left_text = Vips.Image.text("left corner", dpi = 300)
right_text = Vips.Image.text("right corner", dpi = 300)

left = left_text.embed(50, 50, im.width, 150)
right = right_text.embed(im.width - right_text.width - 50, 50, im.width, 150)
footer = (left | right).ifthenelse(black, red, blend = True)

im = im.insert(footer, 0, im.height, expand = True)

im.write_to_file(sys.argv[2])
