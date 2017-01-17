#!/usr/bin/python

import sys

import logging
logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 

a = Vips.Image.black(100, 100)

a.write_to_file("x.v")
