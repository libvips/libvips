#!/usr/bin/python

import sys
from vipsCC import *

im = VImage.VImage (sys.argv[1])

im = im.extract_area (100, 100, im.Xsize () - 200, im.Ysize () - 200)

im = im.affinei_all ("bilinear", 0.9, 0, 0, 0.9, 0, 0)

mask = VMask.VIMask (3, 3, 8, 0, 
		  [-1, -1, -1, 
		   -1,  16, -1, 
		   -1, -1, -1])
im = im.conv (mask)

im.write (sys.argv[2])
