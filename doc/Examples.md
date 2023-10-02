  <refmeta>
    <refentrytitle>Examples</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>libvips</refmiscinfo>
  </refmeta>

  <refnamediv>
    <refname>libvips examples</refname>
    <refpurpose>A few example Python programs using libvips</refpurpose>
  </refnamediv>

This page shows a few libvips examples using Python. They will work with
small syntax changes in any language with a libvips binding.

The libvips test suite is written in Python and exercises every operation
in the API.  It's also a useful source of examples.

# Average a region of interest box on an image

```python
#!/usr/bin/python3

import sys
import pyvips

left = 10
top = 10
width = 64
height = 64

image = pyvips.Image.new_from_file(sys.argv[1])
roi = image.crop(left, top, width, height)
print('average:', roi.avg())
```

# Build huge image mosaic

This makes a 100,000 x 100,000 black image, then inserts all the images you
pass on the command-line into it at random positions. libvips is able to run
this program in sequential mode: it'll open all the input images at the same
time, and stream pixels from them as it needs them to generate the output.

To test it, first make a large 1-bit image. This command will take the
green channel and write as a 1-bit fax image. `wtc.jpg` is a test 10,000
x 10,000 jpeg:

```bash
$ vips extract_band wtc.jpg x.tif[squash,compression=ccittfax4,keep=none] 1
```

Now make 1,000 copies of that image in a subdirectory:

```bash
$ mkdir test
$ for i in {1..1000}; do cp x.tif test/$i.tif; done
```

And run this Python program on them:

```bash
$ time python try255.py x.tif[squash,compression=ccittfax4,strip,bigtiff] test/*
real	1m59.924s
user	4m5.388s
sys	0m8.936s
```

It completes in just under two minutes on this laptop, and needs about
7gb of RAM to run. It would need about the same amount of memory for a
full-colour RGB image, I was just keen to keep disc usage down. 

If you wanted to handle transparency, or if you wanted mixed CMYK and RGB
images, you'd need to do some more work to convert them all into the same
colourspace before inserting them.

```python
#!/usr/bin/python3
#file try255.py

import sys
import random
import pyvips

# this makes a 8-bit, mono image of 100,000 x 100,000 pixels, each pixel zero
im = pyvips.Image.black(100000, 100000)

for filename in sys.argv[2:]:
    tile = pyvips.Image.new_from_file(filename, access='sequential')

    im = im.insert(tile,
                   random.randint(0, im.width - tile.width),
                   random.randint(0, im.height - tile.height))

im.write_to_file(sys.argv[1])
```
