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
  
