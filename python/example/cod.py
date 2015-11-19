#!/usr/bin/python

import sys

import logging
#logging.basicConfig(level = logging.DEBUG)
 
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

#Vips.cache_set_trace(True)

# Run a function expecting a complex image on a two-band image
def run_cmplx(fn, image):
    if image.format == Vips.BandFormat.FLOAT:
        new_format = Vips.BandFormat.COMPLEX
    elif image.format == Vips.BandFormat.DOUBLE:
        new_format = Vips.BandFormat.DPCOMPLEX
    else:
        raise "run_cmplx: not float or double"

    # tag as complex, run, revert tagging
    cmplx = image.copy(bands = 1, format = new_format)
    cmplx_result = fn(cmplx)

    return cmplx_result.copy(bands = 2, format = image.format)

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


