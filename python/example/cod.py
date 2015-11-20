#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)
 
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

#Vips.cache_set_trace(True)

def to_polar(image):
    """Transform image coordinates to polar.

    The image is transformed so that it is wrapped around a point in the
    centre. Vertical straight lines become circles or segments of circles,
    horizontal straight lines become radial spokes.
    """
    # xy image, origin in the centre, scaled to fit image to a circle
    xy = Vips.Image.xyz(image.width, image.height)
    xy -= [image.width / 2.0, image.height / 2.0]
    scale = min(image.width, image.height) / float(image.width)
    xy *= 2.0 / scale

    index = xy.polar()

    # scale vertical axis to 360 degrees
    index *= [1, image.height / 360.0]

    return image.mapim(index)

def to_rectangular(image):
    """Transform image coordinates to rectangular.

    The image is transformed so that it is unwrapped from a point in the
    centre. Circles or segments of circles become vertical straight lines,
    radial lines become horizontal lines.
    """
    # xy image, vertical scaled to 360 degrees
    xy = Vips.Image.xyz(image.width, image.height)
    xy *= [1, 360.0 / image.height]

    index = xy.rect()

    # scale to image rect
    scale = min(image.width, image.height) / float(image.width)
    index *= scale / 2.0
    index += [image.width / 2.0, image.height / 2.0]

    return image.mapim(index)

a = Vips.Image.new_from_file(sys.argv[1])
a = to_polar(a)
a = to_rectangular(a)
a.write_to_file(sys.argv[2])


