#!/usr/bin/python

import sys
from vipsCC import *

im = VImage.VImage (sys.argv[1])

# Crop 100 pixels off all edges.
im = im.extract_area (100, 100, im.Xsize() - 200, im.Ysize() - 200)

# Shrink by 10%
im = im.affine (0.9, 0, 0, 0.9, 0, 0, 0, 0,
        int (im.Xsize() * 0.9), int (im.Ysize() * 0.9))

# sharpen
mask = VMask.VIMask (3, 3, 8, 0, 
		  [-1, -1, -1, 
		   -1,  16, -1, 
		   -1, -1, -1])
im = im.conv (mask)

# write back again
im.write (sys.argv[2])

