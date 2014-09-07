#!/usr/bin/python

import sys

import logging
logging.basicConfig(level = logging.DEBUG)

from gi.repository import GLib
from gi.repository import GObject
from gi.repository import Vips 

from vips8 import vips

a = Vips.Image.black(100, 100)

a.write_to_file("x.v")
