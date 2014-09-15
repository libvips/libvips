#!/usr/bin/python

import sys

#import logging
#logging.basicConfig(level = logging.DEBUG)

from gi.repository import Vips 
from vips8 import vips

im = Vips.Image.new_from_file(sys.argv[1])

im = im | im

black = Vips.Image.black(im.width, 150)
red = black + [255, 0, 0]
left = Vips.Image.text("Left corner").embed(50, 50, im.width, 150)
right_text = Vips.Image.text("Right corner")
right = right_text.embed(im.width - right_text.width - 50, 50, im.width, 150)

footer = (left | right).blend(black, red)

im = im.insert(footer, 0, im.height - footer.height)

im.write_to_file(sys.argv[2])
