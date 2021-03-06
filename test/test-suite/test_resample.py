# vim: set fileencoding=utf-8 :
import pytest

import pyvips
from helpers import JPEG_FILE, OME_FILE, HEIC_FILE, TIF_FILE, all_formats, \
    have, RGBA_FILE, RGBA_CORRECT_FILE, AVIF_FILE


# Run a function expecting a complex image on a two-band image
def run_cmplx(fn, image):
    if image.format == pyvips.BandFormat.FLOAT:
        new_format = pyvips.BandFormat.COMPLEX
    elif image.format == pyvips.BandFormat.DOUBLE:
        new_format = pyvips.BandFormat.DPCOMPLEX
    else:
        raise pyvips.Error("run_cmplx: not float or double")

    # tag as complex, run, revert tagging
    cmplx = image.copy(bands=1, format=new_format)
    cmplx_result = fn(cmplx)

    return cmplx_result.copy(bands=2, format=image.format)


def to_polar(image):
    """Transform image coordinates to polar.

    The image is transformed so that it is wrapped around a point in the
    centre. Vertical straight lines become circles or segments of circles,
    horizontal straight lines become radial spokes.
    """
    # xy image, zero in the centre, scaled to fit image to a circle
    xy = pyvips.Image.xyz(image.width, image.height)
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
    xy = pyvips.Image.xyz(image.width, image.height)
    xy *= [1, 360.0 / image.height]

    # to rect, scale to image rect
    index = run_cmplx(lambda x: x.rect(), xy)
    scale = min(image.width, image.height) / float(image.width)
    index *= scale / 2.0
    index += [image.width / 2.0, image.height / 2.0]

    return image.mapim(index)


class TestResample:
    def test_affine(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        # vsqbs is non-interpolatory, don't test this way
        for name in ["nearest", "bicubic", "bilinear", "nohalo", "lbb"]:
            x = im
            interpolate = pyvips.Interpolate.new(name)
            for i in range(4):
                x = x.affine([0, 1, 1, 0], interpolate=interpolate)

            assert (x - im).abs().max() == 0

    def test_reduce(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)
        # cast down to 0-127, the smallest range, so we aren't messed up by
        # clipping
        im = im.cast(pyvips.BandFormat.CHAR)

        for fac in [1, 1.1, 1.5, 1.999]:
            for fmt in all_formats:
                for kernel in ["nearest", "linear",
                               "cubic", "lanczos2", "lanczos3"]:
                    x = im.cast(fmt)
                    r = x.reduce(fac, fac, kernel=kernel)
                    d = abs(r.avg() - im.avg())
                    assert d < 2

        # try constant images ... should not change the constant
        for const in [0, 1, 2, 254, 255]:
            im = (pyvips.Image.black(10, 10) + const).cast("uchar")
            for kernel in ["nearest", "linear",
                           "cubic", "lanczos2", "lanczos3"]:
                # print "testing kernel =", kernel
                # print "testing const =", const
                shr = im.reduce(2, 2, kernel=kernel)
                d = abs(shr.avg() - im.avg())
                assert d == 0

    def test_resize(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)
        im2 = im.resize(0.25)
        # in py3, round() does not round to nearest in the obvious way, so we
        # have to do it by hand
        assert im2.width == int(im.width / 4.0 + 0.5)
        assert im2.height == int(im.height / 4.0 + 0.5)

        # test geometry rounding corner case
        im = pyvips.Image.black(100, 1)
        x = im.resize(0.5)
        assert x.width == 50
        assert x.height == 1

    def test_shrink(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)
        im2 = im.shrink(4, 4)
        # in py3, round() does not round to nearest in the obvious way, so we
        # have to do it by hand
        assert im2.width == int(im.width / 4.0 + 0.5)
        assert im2.height == int(im.height / 4.0 + 0.5)
        assert abs(im.avg() - im2.avg()) < 1

        im2 = im.shrink(2.5, 2.5)
        assert im2.width == int(im.width / 2.5 + 0.5)
        assert im2.height == int(im.height / 2.5 + 0.5)
        assert abs(im.avg() - im2.avg()) < 1

    @pytest.mark.skipif(not pyvips.at_least_libvips(8, 5),
                        reason="requires libvips >= 8.5")
    def test_thumbnail(self):
        im = pyvips.Image.thumbnail(JPEG_FILE, 100)

        assert im.height == 100
        assert im.bands == 3
        assert im.bands == 3

        # the average shouldn't move too much
        im_orig = pyvips.Image.new_from_file(JPEG_FILE)
        assert abs(im_orig.avg() - im.avg()) < 1

        # make sure we always get the right width
        for height in range(440, 1, -13):
            im = pyvips.Image.thumbnail(JPEG_FILE, height)
            assert im.height == height

        # should fit one of width or height
        im = pyvips.Image.thumbnail(JPEG_FILE, 100, height=300)
        assert im.width == 100
        assert im.height != 300
        im = pyvips.Image.thumbnail(JPEG_FILE, 300, height=100)
        assert im.width != 300
        assert im.height == 100

        # with @crop, should fit both width and height
        im = pyvips.Image.thumbnail(JPEG_FILE, 100,
                                    height=300, crop=True)
        assert im.width == 100
        assert im.height == 300

        im1 = pyvips.Image.thumbnail(JPEG_FILE, 100)
        with open(JPEG_FILE, 'rb') as f:
            buf = f.read()
        im2 = pyvips.Image.thumbnail_buffer(buf, 100)
        assert abs(im1.avg() - im2.avg()) < 1

        # should be able to thumbnail many-page tiff
        im = pyvips.Image.thumbnail(OME_FILE, 100)
        assert im.width == 100
        assert im.height == 38

        # should be able to thumbnail individual pages from many-page tiff
        im1 = pyvips.Image.thumbnail(OME_FILE + "[page=0]", 100)
        assert im1.width == 100
        assert im1.height == 38
        im2 = pyvips.Image.thumbnail(OME_FILE + "[page=1]", 100)
        assert im2.width == 100
        assert im2.height == 38
        assert (im1 - im2).abs().max() != 0 

        # should be able to thumbnail entire many-page tiff as a toilet-roll
        # image
        im = pyvips.Image.thumbnail(OME_FILE + "[n=-1]", 100)
        assert im.width == 100
        assert im.height == 570

        # should be able to thumbnail a single-page tiff in a buffer
        im1 = pyvips.Image.thumbnail(TIF_FILE, 100)
        with open(TIF_FILE, 'rb') as f:
            buf = f.read()
        im2 = pyvips.Image.thumbnail_buffer(buf, 100)
        assert abs(im1.avg() - im2.avg()) < 1

        # linear shrink should work on rgba images
        im1 = pyvips.Image.thumbnail(RGBA_FILE, 64, linear=True)
        im2 = pyvips.Image.new_from_file(RGBA_CORRECT_FILE)
        assert abs(im1.flatten(background=255).avg() - im2.avg()) < 1

        if have("heifload"):
            # this image is orientation 6 ... thumbnail should flip it
            im = pyvips.Image.new_from_file(AVIF_FILE)
            thumb = pyvips.Image.thumbnail(AVIF_FILE, 100)

            # thumb should be portrait 
            assert thumb.width < thumb.height
            assert thumb.height == 100

    def test_similarity(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)
        im2 = im.similarity(angle=90)
        im3 = im.affine([0, -1, 1, 0])
        # rounding in calculating the affine transform from the angle stops
        # this being exactly true
        assert (im2 - im3).abs().max() < 50

    def test_similarity_scale(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)
        im2 = im.similarity(scale=2)
        im3 = im.affine([2, 0, 0, 2])
        assert (im2 - im3).abs().max() == 0

    # added in 8.7
    def test_rotate(self):
        if have("rotate"):
            im = pyvips.Image.new_from_file(JPEG_FILE)
            im2 = im.rotate(90)
            im3 = im.affine([0, -1, 1, 0])
            # rounding in calculating the affine transform from the angle stops
            # this being exactly true
            assert (im2 - im3).abs().max() < 50

    def test_mapim(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        p = to_polar(im)
        r = to_rectangular(p)

        # the left edge (which is squashed to the origin) will be badly
        # distorted, but the rest should not be too bad
        a = r.crop(50, 0, im.width - 50, im.height).gaussblur(2)
        b = im.crop(50, 0, im.width - 50, im.height).gaussblur(2)
        assert (a - b).abs().max() < 40

        # this was a bug at one point, strangely, if executed with debug
        # enabled
        mp = pyvips.Image.xyz(im.width, im.height)
        interp = pyvips.Interpolate.new('bicubic')
        assert im.mapim(mp, interpolate=interp).avg() == im.avg()


if __name__ == '__main__':
    pytest.main()
