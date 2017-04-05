  <refmeta>
    <refentrytitle>Examples</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>libvips</refmiscinfo>
  </refmeta>

  <refnamediv>
    <refname>libvips examples</refname>
    <refpurpose>A few example Python programs using libvips</refpurpose>
  </refnamediv>

This page shows a few libvips examples using Python. They will work with small syntax
changes in any language with a libvips binding. 

The libvips test suite is written in Python and exercises every operation in the API.
It's also a useful source of examples. 

# Average a region of interest box on an image

``` python
#!/usr/bin/env python

import sys
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

left = 10
top = 10
width = 64
height = 64

image = Vips.Image.new_from_file(sys.argv[1])
roi = image.crop(left, top, width, height)
print 'average:', roi.avg()
```

# libvips and numpy

You can use `Vips.Image.new_from_memory_copy()` to make a vips image from an area of
memory. The memory array needs to be laid out band-interleaved, as a set of scanlines,
with no padding between lines. 

This example moves an image from numpy to vips, but it's simple to move the other way
(use `Vips.Image.write_to_memory()`) to to move images into or out of PIL.

```python
#!/usr/bin/python

import numpy 
import scipy.ndimage
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

def np_dtype_to_vips_format(np_dtype):
    '''
    Map numpy data types to VIPS data formats.

    Parameters
    ----------
    np_dtype: numpy.dtype

    Returns
    -------
    gi.overrides.Vips.BandFormat
    '''
    lookup = {
        numpy.dtype('int8'): Vips.BandFormat.CHAR,
        numpy.dtype('uint8'): Vips.BandFormat.UCHAR,
        numpy.dtype('int16'): Vips.BandFormat.SHORT,
        numpy.dtype('uint16'): Vips.BandFormat.USHORT,
        numpy.dtype('int32'): Vips.BandFormat.INT,
        numpy.dtype('float32'): Vips.BandFormat.FLOAT,
        numpy.dtype('float64'): Vips.BandFormat.DOUBLE
    }
    return lookup[np_dtype]

def np_array_to_vips_image(array):
    '''
    Convert a `numpy` array to a `Vips` image object.

    Parameters
    ----------
    nparray: numpy.ndarray

    Returns
    -------
    gi.overrides.Vips.image
    '''
    # Look up what VIPS format corresponds to the type of this np array
    vips_format = np_dtype_to_vips_format(array.dtype)
    dims = array.shape
    height = dims[0]
    width = 1
    bands = 1
    if len(dims) > 1:
        width = dims[1]
    if len(dims) > 2:
        bands = dims[2]
    img = Vips.Image.new_from_memory_copy(array.data, 
        width, height, bands, vips_format)

    return img

array = numpy.random.random((10,10))
vips_image = np_array_to_vips_image(array)
print 'avg =', vips_image.avg()

array = scipy.ndimage.imread("test.jpg")
vips_image = np_array_to_vips_image(array)
print 'avg =', vips_image.avg()
vips_image.write_to_file("test2.jpg")
```

# Watermarking

This example renders a simple watermark on an image. Use it like this:


```
./watermark.py somefile.png output.jpg "hello <i>world</i>"
```

The text is rendered in transparent red pixels all over the image. It knows about
transparency, CMYK, and 16-bit images. 

```python
#!/usr/bin/python
 
import sys
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips
 
im = Vips.Image.new_from_file(sys.argv[1], access = Vips.Access.SEQUENTIAL)
 
text = Vips.Image.text(sys.argv[3], width = 500, dpi = 300)
text = (text * 0.3).cast("uchar")
text = text.embed(100, 100, text.width + 200, text.width + 200)
text = text.replicate(1 + im.width / text.width, 1 + im.height / text.height)
text = text.crop(0, 0, im.width, im.height)

# we want to blend into the visible part of the image and leave any alpha
# channels untouched ... we need to split im into two parts

# 16-bit images have 65535 as white
if im.format == Vips.BandFormat.USHORT:
    white = 65535
else:
    white = 255

# guess how many bands from the start of im contain visible colour information
if im.bands >= 4 and im.interpretation == Vips.Interpretation.CMYK:
    # cmyk image ... put the white into the magenta channel
    n_visible_bands = 4
    text_colour = [0, white, 0, 0]
elif im.bands >= 3:
    # colour image ... put the white into the red channel
    n_visible_bands = 3
    text_colour = [white, 0, 0]
else:
    # mono image
    n_visible_bands = 1
    text_colour = white

# split into image and alpha
if im.bands - n_visible_bands > 0:
    alpha = im.extract_band(n_visible_bands, n = im.bands - n_visible_bands)
    im = im.extract_band(0, n = n_visible_bands)
else:
    alpha = None

# blend means do a smooth fade using the 0 - 255 values in the condition channel
# (test in this case) ... this will render the anit-aliasing
im = text.ifthenelse(text_colour, im, blend = True)

# reattach alpha
if alpha:
    im = im.bandjoin(alpha)
 
im.write_to_file(sys.argv[2])

```

# Build huge image mosaic

This makes a 100,000 x 100,000 black image, then inserts all the images you pass on the
command-line into it at random positions. libvips is able to run this program in
sequential mode: it'll open all the input images at the same time, and stream pixels from
them as it needs them to generate the output. 

To test it, first make a large 1-bit image. This command will take the green channel and
write as a 1-bit fax image. `wtc.jpg` is a test 10,000 x 10,000 jpeg:

```
$ vips extract_band wtc.jpg x.tif[squash,compression=ccittfax4,strip] 1
```

Now make 1,000 copies of that image in a subdirectory:

```
$ mkdir test
$ for i in {1..1000}; do cp x.tif test/$i.tif; done
```

And run this Python program on them:

```
$ time ./try255.py x.tif[squash,compression=ccittfax4,strip,bigtif] test/*
real	1m59.924s
user	4m5.388s
sys	0m8.936s
```

It completes in just under two minutes on this laptop, and needs about
7gb of RAM to run. It would need about the same amount of memory for a
full-colour RGB image, I was just keen to keep disc usage down. 

If you wanted to handle transparency, or if you wanted mixed CMYK and RGB images, you'd 
need to do some more work to convert them all into the same colourspace before 
inserting them.

``` python
#!/usr/bin/env python

import sys
import random

import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

# turn on progress reporting
Vips.progress_set(True)

# this makes a 8-bit, mono image of 100,000 x 100,000 pixels, each pixel zero
im = Vips.Image.black(100000, 100000)

for filename in sys.argv[2:]:
    tile = Vips.Image.new_from_file(filename, access = Vips.Access.SEQUENTIAL)

    im = im.insert(tile,
                   random.randint(0, im.width - tile.width),
                   random.randint(0, im.height - tile.height))

im.write_to_file(sys.argv[1])

```

# Rename DICOM images using header fields

DICOM images commonly come in an awful directory hierarchy named as something
like `images/a/b/e/z04`. There can be thousands of files and it can be very
hard to find the one you want.

This utility copies files to a single flat directory, naming them using
fields from the DICOM header. You can actually find stuff! Useful.

``` python
#!/usr/bin/python

import sys
import re
import os
import shutil

from vipsCC import *

if len (sys.argv) != 3:
  print 'rename DICOM files using tags from the header'
  print 'usage:'
  print '\t%s srcdir destdir' % sys.argv[0]
  print 'the directory tree below srcdir is searched, all files are'
  print 'renamed and put into destdir in a flat list'
  sys.exit (1)

srcdir = sys.argv[1]
destdir = sys.argv[2]

if not os.access (destdir, os.F_OK | os.R_OK | os.W_OK | os.X_OK):
  os.mkdir (destdir)

def get_field (vim, field):
  result = vim.meta_get_string (field)

  # remove any \n etc.
  result = re.sub ("\n", "", result)

  # remove any leading or trailing spaces
  result = re.sub (" $", "", result)
  result = re.sub ("^ ", "", result)

  return result

id_name = "magick-dcm:Patient'sID"
modality_name = "magick-dcm:Modality"
series_name = "magick-dcm:SeriesNumber"
instance_name = "magick-dcm:Instance(formerlyImage)Number"
date_name = "magick-dcm:ImageDate"

n_processed = 0

for (dirpath, dirnames, filenames) in os.walk (srcdir):
  for file in filenames:
    path = os.path.join (dirpath, file)

    try:
      vim = VImage.VImage (path)
    except VError.VError, e:
      print 'unable to open', path
      continue

    try:
      id = get_field (vim, id_name)
      modality = get_field (vim, modality_name)
      series = get_field (vim, series_name)
      instance = get_field (vim, instance_name)
      date = get_field (vim, date_name)
    except VError.VError, e:
      print 'unable to get fields from header', path
      continue

    match = re.match ("(\d\d\d\d)(\d\d)(\d\d)", date)
    date = match.group (1) + "." + match.group (2) + "." + match.group (3)
    newname = id + "." + modality + "." + series + "." + instance + "." + date + ".IMA"

    shutil.copyfile(path, os.path.join (destdir, newname))

    n_processed += 1

print '\t(%d files processed)' % n_processed
```
