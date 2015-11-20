#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)
 
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

#Vips.cache_set_trace(True)

# Run a function expecting a complex image on an image with an even number of
# bands
def run_cmplx(fn, image):
    original_format = image.format

    if not Vips.band_format_iscomplex(image.format):
        if image.bands % 2 != 0:
            raise "not an even number of bands"

        if not Vips.band_format_isfloat(image.format):
            image = image.cast(Vips.BandFormat.FLOAT)

        if image.format == Vips.BandFormat.DOUBLE:
            new_format = Vips.BandFormat.DPCOMPLEX
        else:
            new_format = Vips.BandFormat.COMPLEX

        image = image.copy(format = new_format, bands = image.bands / 2)

    image = fn(image)

    if not Vips.band_format_iscomplex(original_format):
        if image.format == Vips.BandFormat.DPCOMPLEX:
            new_format = Vips.BandFormat.DOUBLE
        else:
            new_format = Vips.BandFormat.FLOAT

        image = image.copy(format = new_format, bands = image.bands * 2)

    return image

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

    # to polar, scale vertical axis to 360 degrees
    index = run_cmplx(lambda x: x.polar(), xy)
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

    # to rect, scale to image rect
    index = run_cmplx(lambda x: x.rect(), xy)
    scale = min(image.width, image.height) / float(image.width)
    index *= scale / 2.0
    index += [image.width / 2.0, image.height / 2.0]

    return image.mapim(index)

a = Vips.Image.new_from_file(sys.argv[1])
a = to_polar(a)
a = to_rectangular(a)
a.write_to_file(sys.argv[2])


