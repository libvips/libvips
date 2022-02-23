# vim: set fileencoding=utf-8 :
# test helpers

import os
import tempfile
import pytest

import pyvips

IMAGES = os.path.join(os.path.dirname(__file__), os.pardir, 'images')
JPEG_FILE = os.path.join(IMAGES, "sample.jpg")
TRUNCATED_FILE = os.path.join(IMAGES, "truncated.jpg")
SRGB_FILE = os.path.join(IMAGES, "sRGB.icm")
MATLAB_FILE = os.path.join(IMAGES, "sample.mat")
PNG_FILE = os.path.join(IMAGES, "sample.png")
TIF_FILE = os.path.join(IMAGES, "sample.tif")
TIF1_FILE = os.path.join(IMAGES, "1bit.tif")
TIF2_FILE = os.path.join(IMAGES, "2bit.tif")
TIF4_FILE = os.path.join(IMAGES, "4bit.tif")
OME_FILE = os.path.join(IMAGES, "multi-channel-z-series.ome.tif")
ANALYZE_FILE = os.path.join(IMAGES, "t00740_tr1_segm.hdr")
GIF_FILE = os.path.join(IMAGES, "cramps.gif")
WEBP_FILE = os.path.join(IMAGES, "1.webp")
WEBP_LOOKS_LIKE_SVG_FILE = os.path.join(IMAGES, "looks-like-svg.webp")
WEBP_ANIMATED_FILE = os.path.join(IMAGES, "big-height.webp")
EXR_FILE = os.path.join(IMAGES, "sample.exr")
FITS_FILE = os.path.join(IMAGES, "WFPC2u5780205r_c0fx.fits")
OPENSLIDE_FILE = os.path.join(IMAGES, "CMU-1-Small-Region.svs")
PDF_FILE = os.path.join(IMAGES, "ISO_12233-reschart.pdf")
CMYK_PDF_FILE = os.path.join(IMAGES, "cmyktest.pdf")
SVG_FILE = os.path.join(IMAGES, "logo.svg")
SVGZ_FILE = os.path.join(IMAGES, "logo.svgz")
SVG_GZ_FILE = os.path.join(IMAGES, "logo.svg.gz")
GIF_ANIM_FILE = os.path.join(IMAGES, "cogs.gif")
GIF_ANIM_EXPECTED_PNG_FILE = os.path.join(IMAGES, "cogs.png")
GIF_ANIM_DISPOSE_BACKGROUND_FILE = os.path.join(IMAGES, "dispose-background.gif")
GIF_ANIM_DISPOSE_BACKGROUND_EXPECTED_PNG_FILE = os.path.join(IMAGES, "dispose-background.png")
GIF_ANIM_DISPOSE_PREVIOUS_FILE = os.path.join(IMAGES, "dispose-previous.gif")
GIF_ANIM_DISPOSE_PREVIOUS_EXPECTED_PNG_FILE = os.path.join(IMAGES, "dispose-previous.png")
DICOM_FILE = os.path.join(IMAGES, "dicom_test_image.dcm")
BMP_FILE = os.path.join(IMAGES, "MARBLES.BMP")
NIFTI_FILE = os.path.join(IMAGES, "avg152T1_LR_nifti.nii.gz")
ICO_FILE = os.path.join(IMAGES, "favicon.ico")
TGA_FILE = os.path.join(IMAGES, "targa.tga")
SGI_FILE = os.path.join(IMAGES, "silicongraphics.sgi")
AVIF_FILE = os.path.join(IMAGES, "avif-orientation-6.avif")
AVIF_FILE_HUGE = os.path.join(IMAGES, "16x17000.avif")
HEIC_FILE = os.path.join(IMAGES, "heic-orientation-6.heic")
RGBA_FILE = os.path.join(IMAGES, "rgba.png")
RGBA_CORRECT_FILE = os.path.join(IMAGES, "rgba-correct.ppm")
MOSAIC_FILES = [os.path.join(IMAGES, "cd1.1.jpg"), os.path.join(IMAGES, "cd1.2.jpg"),
                os.path.join(IMAGES, "cd2.1.jpg"), os.path.join(IMAGES, "cd2.2.jpg"),
                os.path.join(IMAGES, "cd3.1.jpg"), os.path.join(IMAGES, "cd3.2.jpg"),
                os.path.join(IMAGES, "cd4.1.jpg"), os.path.join(IMAGES, "cd4.2.jpg")]
MOSAIC_MARKS = [[489, 140], [66, 141],
                [453, 40], [15, 43],
                [500, 122], [65, 121],
                [495, 58], [40, 57]]
MOSAIC_VERTICAL_MARKS = [[388, 44], [364, 346],
                         [384, 17], [385, 629],
                         [527, 42], [503, 959]]
JP2K_FILE = os.path.join(IMAGES, "world.jp2")

unsigned_formats = [pyvips.BandFormat.UCHAR,
                    pyvips.BandFormat.USHORT,
                    pyvips.BandFormat.UINT]
signed_formats = [pyvips.BandFormat.CHAR,
                  pyvips.BandFormat.SHORT,
                  pyvips.BandFormat.INT]
float_formats = [pyvips.BandFormat.FLOAT,
                 pyvips.BandFormat.DOUBLE]
complex_formats = [pyvips.BandFormat.COMPLEX,
                   pyvips.BandFormat.DPCOMPLEX]
int_formats = unsigned_formats + signed_formats
noncomplex_formats = int_formats + float_formats
all_formats = int_formats + float_formats + complex_formats

colour_colourspaces = [pyvips.Interpretation.XYZ,
                       pyvips.Interpretation.LAB,
                       pyvips.Interpretation.LCH,
                       pyvips.Interpretation.CMC,
                       pyvips.Interpretation.LABS,
                       pyvips.Interpretation.SCRGB,
                       pyvips.Interpretation.HSV,
                       pyvips.Interpretation.SRGB,
                       pyvips.Interpretation.YXY]
cmyk_colourspaces = [pyvips.Interpretation.CMYK]
coded_colourspaces = [pyvips.Interpretation.LABQ]
mono_colourspaces = [pyvips.Interpretation.B_W]
sixteenbit_colourspaces = [pyvips.Interpretation.GREY16,
                           pyvips.Interpretation.RGB16]
all_colourspaces = colour_colourspaces + mono_colourspaces + \
                   coded_colourspaces + sixteenbit_colourspaces + \
                   cmyk_colourspaces

max_value = {pyvips.BandFormat.UCHAR: 0xff,
             pyvips.BandFormat.USHORT: 0xffff,
             pyvips.BandFormat.UINT: 0xffffffff,
             pyvips.BandFormat.CHAR: 0x7f,
             pyvips.BandFormat.SHORT: 0x7fff,
             pyvips.BandFormat.INT: 0x7fffffff,
             pyvips.BandFormat.FLOAT: 1.0,
             pyvips.BandFormat.DOUBLE: 1.0,
             pyvips.BandFormat.COMPLEX: 1.0,
             pyvips.BandFormat.DPCOMPLEX: 1.0}

sizeof_format = {pyvips.BandFormat.UCHAR: 1,
                 pyvips.BandFormat.USHORT: 2,
                 pyvips.BandFormat.UINT: 4,
                 pyvips.BandFormat.CHAR: 1,
                 pyvips.BandFormat.SHORT: 2,
                 pyvips.BandFormat.INT: 4,
                 pyvips.BandFormat.FLOAT: 4,
                 pyvips.BandFormat.DOUBLE: 8,
                 pyvips.BandFormat.COMPLEX: 8,
                 pyvips.BandFormat.DPCOMPLEX: 16}

rot45_angles = [pyvips.Angle45.D0,
                pyvips.Angle45.D45,
                pyvips.Angle45.D90,
                pyvips.Angle45.D135,
                pyvips.Angle45.D180,
                pyvips.Angle45.D225,
                pyvips.Angle45.D270,
                pyvips.Angle45.D315]

rot45_angle_bonds = [pyvips.Angle45.D0,
                     pyvips.Angle45.D315,
                     pyvips.Angle45.D270,
                     pyvips.Angle45.D225,
                     pyvips.Angle45.D180,
                     pyvips.Angle45.D135,
                     pyvips.Angle45.D90,
                     pyvips.Angle45.D45]

rot_angles = [pyvips.Angle.D0,
              pyvips.Angle.D90,
              pyvips.Angle.D180,
              pyvips.Angle.D270]

rot_angle_bonds = [pyvips.Angle.D0,
                   pyvips.Angle.D270,
                   pyvips.Angle.D180,
                   pyvips.Angle.D90]


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


# run a 1-ary function on a thing -- loop over elements if the
# thing is a list
def run_fn(fn, x):
    if isinstance(x, list):
        return [fn(i) for i in x]
    else:
        return fn(x)


# make a temp filename with the specified suffix and in the
# specified directory
def temp_filename(directory, suffix):
    temp_name = next(tempfile._get_candidate_names())
    filename = os.path.join(directory, temp_name + suffix)

    return filename


# test for an operator exists
def have(name):
    return pyvips.type_find("VipsOperation", name) != 0


def skip_if_no(operation_name):
    return pytest.mark.skipif(not have(operation_name),
                        reason='no {}, skipping test'.format(operation_name))


# run a 2-ary function on two things -- loop over elements pairwise if the
# things are lists
def run_fn2(fn, x, y):
    if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
        return fn(x, y)
    elif isinstance(x, list) or isinstance(y, list):
        return [fn(i, j) for i, j in zip_expand(x, y)]
    else:
        return fn(x, y)


# test a pair of things which can be lists for approx. equality
def assert_almost_equal_objects(a, b, threshold=0.0001, msg=''):
    # print('assertAlmostEqualObjects %s = %s' % (a, b))
    assert all([pytest.approx(x, abs=threshold) == y
                for x, y in zip_expand(a, b)]), msg


# test a pair of things which can be lists for equality
def assert_equal_objects(a, b, msg=''):
    # print 'assertEqualObjects %s = %s' % (a, b)
    assert all([x == y for x, y in zip_expand(a, b)]), msg


# test a pair of things which can be lists for difference less than a
# threshold
def assert_less_threshold(a, b, diff):
    assert all([abs(x - y) < diff for x, y in zip_expand(a, b)])


# run a function on an image and on a single pixel, the results
# should match
def run_cmp(message, im, x, y, fn):
    a = im(x, y)
    v1 = fn(a)
    im2 = fn(im)
    v2 = im2(x, y)
    assert_almost_equal_objects(v1, v2, msg=message)


# run a function on an image,
# 50,50 and 10,10 should have different values on the test image
def run_image(message, im, fn):
    run_cmp(message, im, 50, 50, fn)
    run_cmp(message, im, 10, 10, fn)


# run a function on (image, constant), and on (constant, image).
# 50,50 and 10,10 should have different values on the test image
def run_const(message, fn, im, c):
    run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, x, c))
    run_cmp(message, im, 50, 50, lambda x: run_fn2(fn, c, x))
    run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, x, c))
    run_cmp(message, im, 10, 10, lambda x: run_fn2(fn, c, x))


# run a function on a pair of images and on a pair of pixels, the results
# should match
def run_cmp2(message, left, right, x, y, fn):
    a = left(x, y)
    b = right(x, y)
    v1 = fn(a, b)
    after = fn(left, right)
    v2 = after(x, y)
    assert_almost_equal_objects(v1, v2, msg=message)


# run a function on a pair of images
# 50,50 and 10,10 should have different values on the test image
def run_image2(message, left, right, fn):
    run_cmp2(message, left, right, 50, 50,
             lambda x, y: run_fn2(fn, x, y))
    run_cmp2(message, left, right, 10, 10,
             lambda x, y: run_fn2(fn, x, y))
