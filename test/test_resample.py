#!/usr/bin/python
# vim: set fileencoding=utf-8 :

import unittest
import math

#import logging
#logging.basicConfig(level = logging.DEBUG)

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips 

Vips.leak_set(True)

unsigned_formats = [Vips.BandFormat.UCHAR, 
                    Vips.BandFormat.USHORT, 
                    Vips.BandFormat.UINT] 
signed_formats = [Vips.BandFormat.CHAR, 
                  Vips.BandFormat.SHORT, 
                  Vips.BandFormat.INT] 
float_formats = [Vips.BandFormat.FLOAT, 
                 Vips.BandFormat.DOUBLE]
complex_formats = [Vips.BandFormat.COMPLEX, 
                   Vips.BandFormat.DPCOMPLEX] 
int_formats = unsigned_formats + signed_formats
noncomplex_formats = int_formats + float_formats
all_formats = int_formats + float_formats + complex_formats

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
    # xy image, zero in the centre, scaled to fit image to a circle
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

# an expanding zip ... if either of the args is a scalar or a one-element list,
# duplicate it down the other side 
def zip_expand(x, y):
    # handle singleton list case
    if isinstance(x, list) and len(x) == 1:
        x = x[0]
    if isinstance(y, list) and len(y) == 1:
        y = y[0]

    if isinstance(x, list) and isinstance(y, list):
        return list(zip(x, y))
    elif isinstance(x, list):
        return [[i, y] for i in x]
    elif isinstance(y, list):
        return [[x, j] for j in y]
    else:
        return [[x, y]]

class TestResample(unittest.TestCase):
    # test a pair of things which can be lists for approx. equality
    def assertAlmostEqualObjects(self, a, b, places = 4, msg = ''):
        # print 'assertAlmostEqualObjects %s = %s' % (a, b)
        for x, y in zip_expand(a, b):
            self.assertAlmostEqual(x, y, places = places, msg = msg)

    def setUp(self):
        self.jpeg_file = "images/йцук.jpg"
        self.rotated_jpeg_file = "images/Landscape_6.jpg"

    def test_affine(self):
        im = Vips.Image.new_from_file(self.jpeg_file)

        # vsqbs is non-interpolatory, don't test this way
        for name in ["nearest", "bicubic", "bilinear", "nohalo", "lbb"]:
            x = im
            interpolate = Vips.Interpolate.new(name)
            for i in range(4):
                x = x.affine([0, 1, 1, 0], interpolate = interpolate)
 
            self.assertEqual((x - im).abs().max(), 0)

    def test_reduce(self):
        im = Vips.Image.new_from_file(self.jpeg_file)
        # cast down to 0-127, the smallest range, so we aren't messed up by
        # clipping
        im = im.cast(Vips.BandFormat.CHAR)
        bicubic = Vips.Interpolate.new("bicubic")
        bilinear = Vips.Interpolate.new("bilinear")
        nearest = Vips.Interpolate.new("nearest")

        for fac in [1, 1.1, 1.5, 1.999]:
            for fmt in all_formats:
                x = im.cast(fmt)
                r = x.reduce(fac, fac, kernel = "cubic")
                a = x.affine([1.0 / fac, 0, 0, 1.0 / fac], 
                             interpolate = bicubic,
                             oarea = [0, 0, x.width / fac, x.height / fac])
                d = (r - a).abs().max()
                self.assertLess(d, 10)

        for fac in [1, 1.1, 1.5, 1.999]:
            for fmt in all_formats:
                x = im.cast(fmt)
                r = x.reduce(fac, fac, kernel = "linear")
                a = x.affine([1.0 / fac, 0, 0, 1.0 / fac], 
                             interpolate = bilinear,
                             oarea = [0, 0, x.width / fac, x.height / fac])
                d = (r - a).abs().max()
                self.assertLess(d, 10)

        # for other kernels, just see if avg looks about right
        for fac in [1, 1.1, 1.5, 1.999]:
            for fmt in all_formats:
                for kernel in ["nearest", "lanczos2", "lanczos3"]:
                    x = im.cast(fmt)
                    r = x.reduce(fac, fac, kernel = kernel)
                    d = abs(r.avg() - im.avg())
                    self.assertLess(d, 2)

        # try constant images ... should not change the constant
        for const in [0, 1, 2, 254, 255]:
            im = (Vips.Image.black(10, 10) + const).cast("uchar")
            for kernel in ["nearest", "linear", "cubic", "lanczos2", "lanczos3"]:
                # print "testing kernel =", kernel
                # print "testing const =", const
                shr = im.reduce(2, 2, kernel = kernel)
                d = abs(shr.avg() - im.avg())
                self.assertEqual(d, 0)

    def test_resize(self):
        im = Vips.Image.new_from_file(self.jpeg_file)
        im2 = im.resize(0.25)
        self.assertEqual(im2.width, round(im.width / 4.0))
        self.assertEqual(im2.height, round(im.height / 4.0))

        # test geometry rounding corner case
        im = Vips.Image.black(100, 1);
        x = im.resize(0.5)
        self.assertEqual(x.width, 50)
        self.assertEqual(x.height, 1)

    def test_shrink(self):
        im = Vips.Image.new_from_file(self.jpeg_file)
        im2 = im.shrink(4, 4)
        self.assertEqual(im2.width, round(im.width / 4.0))
        self.assertEqual(im2.height, round(im.height / 4.0))
        self.assertTrue(abs(im.avg() - im2.avg()) < 1)

        im2 = im.shrink(2.5, 2.5)
        self.assertEqual(im2.width, round(im.width / 2.5))
        self.assertEqual(im2.height, round(im.height / 2.5))
        self.assertLess(abs(im.avg() - im2.avg()), 1)

    def test_thumbnail(self):
        im = Vips.Image.thumbnail(self.jpeg_file, 100)

        self.assertEqual(im.width, 100)
        self.assertEqual(im.bands, 3)
        self.assertEqual(im.bands, 3)

        # the average shouldn't move too much
        im_orig = Vips.Image.new_from_file(self.jpeg_file)
        self.assertLess(abs(im_orig.avg() - im.avg()), 1)

        # make sure we always get the right width
        for width in range(1000, 1, -13):
            im = Vips.Image.thumbnail(self.jpeg_file, width)
            self.assertEqual(im.width, width)

        # should fit one of width or height
        im = Vips.Image.thumbnail(self.jpeg_file, 100, height = 300)
        self.assertEqual(im.width, 100)
        self.assertNotEqual(im.height, 300)
        im = Vips.Image.thumbnail(self.jpeg_file, 300, height = 100)
        self.assertNotEqual(im.width, 300)
        self.assertEqual(im.height, 100)

        # force should fit width and height ... although this jpg has an
        # orientation tag, we ignore it unless autorot is on
        im = Vips.Image.thumbnail(self.rotated_jpeg_file, 100, height = 300,
                                  size = "force")
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 300)

        # with force + autorot, we spin the image, but the output size should
        # not change
        im = Vips.Image.thumbnail(self.rotated_jpeg_file, 100, height = 300,
                                  size = "force", auto_rotate = True)
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 300)

        # with @crop, should fit both width and height
        im = Vips.Image.thumbnail(self.jpeg_file, 100, 
                                  height = 300, crop = "centre")
        self.assertEqual(im.width, 100)
        self.assertEqual(im.height, 300)

        # with size up, should not downsize
        im = Vips.Image.thumbnail(self.jpeg_file, 100, size = "up")
        self.assertEqual(im.width, im_orig.width)
        im = Vips.Image.thumbnail(self.jpeg_file, 10000, size = "up")
        self.assertEqual(im.width, 10000)

        # with size down, should not upsize
        im = Vips.Image.thumbnail(self.jpeg_file, 100, size = "down")
        self.assertEqual(im.width, 100)
        im = Vips.Image.thumbnail(self.jpeg_file, 10000, size = "down")
        self.assertEqual(im.width, im_orig.width)

        im1 = Vips.Image.thumbnail(self.jpeg_file, 100)
        with open(self.jpeg_file, 'rb') as f:
            buf = f.read()
        im2 = Vips.Image.thumbnail_buffer(buf, 100)
        self.assertLess(abs(im1.avg() - im2.avg()), 1)

    def test_similarity(self):
        im = Vips.Image.new_from_file(self.jpeg_file)
        im2 = im.similarity(angle = 90)
        im3 = im.affine([0, -1, 1, 0])
        # rounding in calculating the affine transform from the angle stops 
        # this being exactly true
        self.assertLess((im2 - im3).abs().max(), 50)

    def test_similarity_scale(self):
        im = Vips.Image.new_from_file(self.jpeg_file)
        im2 = im.similarity(scale = 2)
        im3 = im.affine([2, 0, 0, 2])
        self.assertEqual((im2 - im3).abs().max(), 0)

    def test_mapim(self):
        im = Vips.Image.new_from_file(self.jpeg_file)

        p = to_polar(im)
        r = to_rectangular(p)

        # the left edge (which is squashed to the origin) will be badly
        # distorted, but the rest should not be too bad
        a = r.crop(50, 0, im.width - 50, im.height).gaussblur(2)
        b = im.crop(50, 0, im.width - 50, im.height).gaussblur(2)
        self.assertLess((a - b).abs().max(), 20)

if __name__ == '__main__':
    unittest.main()
