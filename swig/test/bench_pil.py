#!/usr/bin/python

import Image, sys
import ImageFilter 

im = Image.open (sys.argv[1])

# Crop 100 pixels off all edges.
im = im.crop ((100, 100, im.size[0] - 100, im.size[1] - 100))

# Shrink by 10%
im = im.resize ((int (im.size[0] * 0.9), int (im.size[1] * 0.9)),
        Image.BILINEAR) 

# sharpen
filter = ImageFilter.Kernel ((3, 3),
	      (-1, -1, -1,
	       -1, 16, -1,
	       -1, -1, -1))
im = im.filter (filter)

# write back again
im.save (sys.argv[2])

