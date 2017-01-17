#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 

a = Vips.Image.black(100, 100)
b = a.bandjoin(2)

b.write_to_file("x.v")

txt = Vips.Image.text("left corner", dpi = 300)

c = txt.ifthenelse(2, [0, 255, 0], blend = True)

c.write_to_file("x2.v")
