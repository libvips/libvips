---
title: What's new in 8.12
---

libvips 8.12 is almost done, so here's a quick overview of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Many thanks to Andrewsville, lovell, LionelArn2, vibbix, manthey,
martimpassos, indus, hroskes, kleisauke and others for their great work on
this release.

# Better GIF save

Previous libvips versions have used imagemagick for GIF save. This worked
well, but was slow and needed a *lot* of memory. 

For example, with `3198.gif`, a 140 frame video clip with 300 x 200 pixels per
frame, I saw:

```
$ /usr/bin/time -f %M:%e vipsthumbnail 3198.gif[n=-1] --size 128 -o x.gif
221668:5.57
```

That's 220 MB of memory and 5.6s of real time to make a 128 x 128 thumbnail
video.

Thanks to work by lovell, libvips now has a specialized GIF writer using the
[cgif](https://github.com/dloebl/cgif) library. I see:

```
$ /usr/bin/time -f %M:%e vipsthumbnail 3198.gif[n=-1] --size 128 -o x.gif
56108:2.46
```

So now it's 56 MB peak memory use, and 2.5s -- twice the speed, and only 25% of
the memory use. 

# Much lower memory and file descriptor use for join operations

libvips has supported minimisation signals for a while now. At the end of
a save operation, for example, the saver will emit a `minimise` signal,
and operations along the pipeline will do things like dropping caches and
closing file descriptors.  In 8.12, we've expanded the use of this system
to help improve the performance of operations like `arrayjoin`.

## The problem

For example, here's how you might use `arrayjoin` to untile a google maps
pyramid:

```python
#!/usr/bin/python3

# untile a google maps pyramid

import sys
import os
import pyvips

if len(sys.argv) != 3:
    print("usage: untile-google.py ~/pics/somepyramid out.jpg")
    sys.exit(1)

indir = sys.argv[1]
outfile = sys.argv[2]

# open the blank tile
blank = pyvips.Image.new_from_file(f"{indir}/blank.png")

# find number of pyramid layers
n_layers = 0
for layer in range(1000):
    if not os.path.isdir(f"{indir}/{layer}"):
        n_layers = layer
        break
print(f"{n_layers} layers detected")
if n_layers < 1:
    print("no layers found!")
    sys.exit(1)

# find size of largest layer
max_y = 0
for filename in os.listdir(f"{indir}/{n_layers - 1}"):
    max_y = max(max_y, int(filename))
max_x = 0
for filename in os.listdir(f"{indir}/{n_layers - 1}/0"):
    noext = os.path.splitext(filename)[0]
    max_x = max(max_x, int(noext))
print(f"{max_x + 1} tiles across, {max_y + 1} tiles down")

tiles = []
for y in range(max_y + 1):
    for x in range(max_x + 1):
        tile_name = f"{indir}/{n_layers - 1}/{y}/{x}.jpg"
        if os.path.isfile(tile_name):
            tile = pyvips.Image.new_from_file(tile_name,
                                              access="sequential")
        else:
            tile = blank
        tiles.append(tile)

image = pyvips.Image.arrayjoin(tiles,
                               across=max_x + 1, background=255)

image.write_to_file(outfile)
```

You can run it like this:

```
$ vips dzsave ../st-francis.jpg x --layout google
$ /usr/bin/time -f %M:%e ~/try/untile-google.py x x.jpg
8 layers detected
118 tiles across, 103 tiles down
4487744:15.24
```

So libvips 8.11 joined 12,154 tiles in about 15s, and needed 4.5 GB of memory.

There's another, less obvious problem: this program will need a file
descriptor for every tile. You can see with a small shell script:

```sh
#!/bin/bash

~/try/untile-google.py x x.jpg &
pid=$!

while test -d /proc/$pid; do
  ls /proc/$pid/fd | wc
  sleep 0.1
done
```

This runs the program above and counts the number of open file descriptors 10
times a second. It peaks at over 12,000 open descriptors!  You'll probably
need to make some tricky changes to your machine if you want to be able to
run things like this.

## Minimise during processing

In libvips 8.12, `arrayjoin` will emit `minimise` signals during
processing. It detects that it is operating in a sequential context, and
will signal minimise on an input when the point of processing is past an
input tile. This means that input image resources are discarded during
computation, not just at the end.

With libvips 8.12, I see:

```
$ /usr/bin/time -f %M:%e ~/try/untile-google.py x x.jpg
8 layers detected
118 tiles across, 103 tiles down
2089992:14.66
```

So less than half the memory use, and even a little quicker. 

The saving in file descriptors is even better: it peaks at under 600. That's
low enough to be well inside the limit on most machines, so you'll no longer
need to reconfigure your server to do operations like this.

This is quite a general system, and operations like `insert`, `join` and
`merge` all benefit.

# Other improvements to loaders and savers

As usual, there have been many small improvements to file format support.

- The TIFF writer has better progress feedback for many-page images.
- The JPEG writer has a new option to set the restart interval.
- `dzsave` now supports IIIF3.
- The PPM writer has an option to set the exact save format, and is better at
  picking the correct format for you automatically.
- The jpeg2000 loader is much better with very large, untiled images.
- EXIF support is fixed for string fields containing metacharacters.
- A new `fail-on` flag gives better control over detecting load errors. You
  can spot image truncation easily now.
- Target save is better at picking the write format automatically. 

# More trigonometric functions

Thanks to work by indus and hroskes, libvips now supports `atan2` and has
a full set of hyperbolic trig functions.

# Minor improvements

And of course other minor features and bug fixes. The 
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.

