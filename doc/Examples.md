  <refmeta>
    <refentrytitle>Using `vipsthumbnail`</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>libvips</refmiscinfo>
  </refmeta>

  <refnamediv>
    <refname>`vipsthumbnail`</refname>
    <refpurpose>Introduction to `vipsthumbnail`, with examples</refpurpose>
  </refnamediv>

This page shows a few examples of using VIPS from Python.

# Average a region of interest box on an image

``` python
#!/usr/bin/env python

import sys
import gi
gi.require_version('Vips', '8.0')
from gi.repository import Vips

roix = 10
roiy = 10
roiw = 64
roih = 64

image = Vips.Image.new_from_file(sys.argv[1])
roi = image.crop(roix, roiy, roiw, roih)
print 'average: ', roi.avg()
```

# VIPS and PIL

This script moves an image between PIL and VIPS.

``` python
#!/usr/bin/python

import sys

from vipsCC import *
import Image

# try this 1,000 times and check for leaks
for i in range (0,1000):
  vim = VImage.VImage (sys.argv[1])

  # do some processing in vips ... cut out a small piece of image
  vim = vim.extract_area (500, 500, 100, 100)

  # make a PIL image
  # we use Image.frombuffer (), so PIL is using vim's memory
  # you need to be very careful not to destroy vim until you're done with pim
  # ideally you should make a proxy class that wraps this lifetime problem up
  mode = VImage.PIL_mode_from_vips (vim)
  size = (vim.Xsize (), vim.Ysize ())
  data = vim.tobuffer ()
  pim = Image.frombuffer (mode, size, data, 'raw', mode, 0, 1)

  # rotate 12 degrees with PIL
  pim = pim.rotate (12, Image.BILINEAR, 1)

  # back to vips again
  # PIL doesn't have a tobuffer method, so we have to use tostring to copy the
  # data out of PIL and then fromstring to copy back into VIPS
  str = pim.tostring ()
  bands, format, type = VImage.vips_from_PIL_mode (pim.mode)
  width, height = pim.size
  vim2 = VImage.VImage.fromstring (str, width, height, bands, format)

  # finally write from vips
  vim2.write (sys.argv[2])
```

Leak testing
------------

This loads an image, does some simple processing, and saves again. Handy for leak testing.

``` python
#!/usr/bin/python

import sys

# just need this for leaktesting
import gc

from vipsCC import *

if len (sys.argv) != 3:
  print 'usage:', sys.argv[0], 'inputimage outputimage'
  sys.exit (1)

try:
  a = VImage.VImage (sys.argv[1])
  b = a.invert ()
  c = b.lin ([1,2,3],[4,5,6])
  m = VMask.VIMask (3, 3, 1, 0,
          [-1, -1, -1,
         -1,  8, -1,
         -1, -1, -1])
  d = a.conv (m)
  d.write (sys.argv[2])
except VError.VError, e:
  e.perror (sys.argv[0])

# we can get properties of VImage too
print 'inputimage is', a.Xsize (), 'pixels across'

print 'starting shutdown ...'
del b
del a
del c
del d
del m
# sometimes have to do several GCs to get them all, not sure why
for i in range(10):
  gc.collect ()
print 'shutdown!'

print 'leaked IMAGEs:'
VImage.im__print_all ()
print 'done ... hopefully you saw no leaks'
```

Build image mosaic
------------------

This loads a lot of images (RGB or greyscale) and pastes them at random positions in a 10,000 by 10,000 pixel output image. 8-bit only, but it'd be easy to change that.

``` python
#!/usr/bin/python

import sys
import random
from vipsCC import *

# the size of the image we build
size = 10000

try:
   if len(sys.argv) < 3:
      print 'usage:', sys.argv[0], 'outfile infile1 ...'
      sys.exit (1)

   # make the background image
   bg = VImage.VImage.black (size, size, 3)

   # paste each argument in
   for file in sys.argv[2:]:
      im = VImage.VImage (file)

      # is this a mono image? convert to RGB by joining three of them
      # together
      if im.Bands() == 1:
         im = im.bandjoin (im).bandjoin (im)

      x = random.randint (0, size - im.Xsize () - 1)
      y = random.randint (0, size - im.Ysize () - 1)
      bg = bg.insert_noexpand (im, x, y)

   # write result
   bg.write (sys.argv[1])

except VError.VError, e:
   e.perror (sys.argv[0])
```

Build image pyramid
-------------------

This makes a tiled image pyramid, with each tile in a separate 512x512 pixel file.

``` python
#!/usr/bin/python

import sys
from vipsCC import *

tilesize = 512
maxlevel = 100

try:
   im = VImage.VImage (sys.argv[1])

   for level in range (maxlevel, -1, -1):
      print "Creating tiles for level", level

      # loop to create the tiles
      for y in range (0, im.Ysize(), tilesize):
         for x in range (0, im.Xsize(), tilesize):
            filename = '%dx%d_y%d.jpg' % (level, x / tilesize, y / tilesize)
            # clip tilesize against image size
            width = min (im.Xsize () - x, tilesize)
            height = min (im.Ysize () - y, tilesize)

            # expand edge tiles up to the full tilesize ... Google maps likes this
            # im.extract_area (x, y, width, height).embed(0, 0, 0, tilesize, tilesize).write(filename)

            # let edge tiles be smaller than the full tile size, tiff tiling prefers this
            im.extract_area (x, y, width, height).write (filename)

      # was there only a single tile? we are done
      if im.Xsize() <= tilesize and im.Ysize() <= tilesize:
         break

      # create next pyramid level in RAM
      shrink = im.rightshift_size (1, 1, im.BandFmt())
      im = shrink.write (VImage.VImage ("temp", "t"))

except VError.VError, e:
   e.perror (sys.argv[0])
```

Rename DICOM images using header fields
---------------------------------------

DICOM images commonly come in an awful directory hierarchy named as something like images/a/b/e/z04. There can be thousands of files and it can be very hard to find the one you want.

This utility copies files to a single flat directory, naming them using fields from the DICOM header. You can actually find stuff! Useful.

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
