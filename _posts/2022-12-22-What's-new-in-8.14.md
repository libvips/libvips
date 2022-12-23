---
title: What's new in libvips 8.14
---

libvips 8.14 is almost done, so here's a summary of what's new. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

The headline features are the final switch to meson build system, a new
thread pool and thread recycling system, some useful speedups to `dzsave` and
TIFF load, and the usual small improvements to image format support. Details
below!

We need to thank aksdb, dloebl, ewelot, tlsa, remicollet, DarthSim,
ejoebstl, lovell, shado23, kleisauke, and others for their great work on
this release.

# Build system changes

The previous release added a meson build system alongside the autotools build
system we'd used for decades. This release removes the autotools system
completely, and a lot of other old stuff too, so it's now meson all the way
down.

The README has some notes to help you get started if you need to build from
source, but the quick summary is something like:

```
cd libvips-x.y.x
meson setup build --prefix /my/install/prefix
cd build
meson compile
meson test
meson install
```

# Enhancements to operators

Printers usually work with four colours: cyan, magenta, yellow and black.
libvips has supported (via [LittleCMS](https://www.littlecms.com/))
conversion to and from CMYK images for a long time.

In 8.14 we've added support for N-colour profiles. These profiles add extra
colours, usually the complements of CMY, to expand the colour gamut available
and reduce dithering effects. The `icc_transform` set of operators now 
support rendering to and from N-colour device images in the obvious way.

The TIFF saver also knows how to read and write these CMYRGK (for example)
files, and hopefully does it in a way that's compatible with PhotoShop.

With [this sample 6CLR
profile](https://github.com/libvips/libvips/files/9550789/6clr-test.icc.zip)
I can run:

```
$ vips icc_export nina.jpg x.tif --output-profile 6clr-test.icc
```

To make an image split to 6 colour separations:

```
$ tiffinfo x.tif
=== TIFF directory 0 ===
TIFF Directory at offset 0x8b89008 (146313224)
  Image Width: 6048 Image Length: 4032
  Resolution: 300, 300 pixels/inch
  Bits/Sample: 8
  Sample Format: unsigned integer
  Compression Scheme: None
  Photometric Interpretation: separated
  Extra Samples: 2<unassoc-alpha, unassoc-alpha>
  Orientation: row 0 top, col 0 lhs
  Samples/Pixel: 6
  Rows/Strip: 128
  Planar Configuration: single image plane
  InkSet: 1
  ICC Profile: <present>, 13739188 bytes
```

We've also added support for character as well as word wrapping
to `vips_text()` with the `wrap` parameter, added an `rgb` mode to
`vips_openslideload()`, and `vips_smartcrop()` now optionally returns the
location of interest in attention-based cropping.

# Improvements to the libvips core

## Faster threading

There has been a major change to the libvips core: we have a new threadpool
system. The new threadpool has several very useful new features:

1. Thread pools now resize dynamically. Each threadpool is able to tell how 
   busy their workers are, and is able to either size up or size down 
   depending on load. The old `vips-concurrency` setting now sets the maximum
   threadpool size.

   The aim is to prevent libvips having a lot of idle threads on machines with
   many cores. Why create 16 workers for a pipeline that only has a small
   amount of parallelism? 

   Few idle threads means libvips should make better use of hardware resources
   on large machines with complex mixed workloads. The new threadpool should
   also be a bit quicker.

2. You can also set hints for the amount of parallelism you expect in a
   pipeline. Again, this help prevent overcomitting of thread resources.

3. Finally, there's a new thread recycling system. Some platforms have very
   slow or tricky thread start and stop, so rather than killing and recreating
   threads all the time, libvips will make a set of threads and then recycle
   them.

   We had a thread recycling system before, but this new one should be
   noticably faster.

We've used this new threading system to revise `dzsave`, and it's now quite a
bit quicker. Here's the previous release, libvips 8.13, running on a
46,000 x 32,914 pixel slide image:

```
$ /usr/bin/time -f %M:%e vips dzsave CMU-1.svs x
881892:36.65
```

That's 900mb of peak memory and 37s of run time. Here's libvips 8.14:

```
$ /usr/bin/time -f %M:%e vips dzsave CMU-1.svs x
704360:19.50
```

Almost twice as fast, and noticably lower memory use. This all comes from the
new threading system.

This new release has another feature which can improve slide read
performance: the `rgb` flag to openslideload. This drops the redundant alpha 
plane earlier, saving time and memory:

```
$ /usr/bin/time -f %M:%e vips dzsave CMU-1.svs[rgb] x
547832:13.02
```

Now it's three times faster than 8.13 and runs in about half the memory.

## Faster TIFF load

The previous libvips used libtiff to fetch decoded tiles from compressed 
TIFF files. This ran the decompressor inside the libtiff lock, so it was
single threaded.

For libvips 8.14, we've moved jpeg2000 and jpeg decompression outside the
libtiff lock so they now run multi-threaded. This gives a really nice speedup.

First, make a large, tiled, JPEG-compressed TIFF:

```
$ vips copy CMU-1.svs[rgb] x.tif[tile,compression=jpeg]
```

Then read the file and compute the pixel average. Here's the previous 8.13
release:

```
$ time vips avg x.tif 
226.581443

real    0m42.776s
user    0m48.380s
sys 0m0.428s
```

You can see that the total CPU time (the `user` line) is almost equal to the
real clock time (the `real` line), so there was very little parallelism. It
was able to parallelize the computation of the average value, but the
decompress (which was most of the run time) was single threaded.

Here's 8.14:

```
$ time vips avg x.tif 
226.581443

real	0m3.371s
user	0m17.413s
sys	0m1.573s
```

Now tiles are decompressed in parallel and on this 16-core PC there's a
huge speedup, more than 10x. Zoom!

This is just accelerating TIFF load. Perhaps TIFF save will get the same
treatment in the next version.

## bash completions

This won't appeal to many people, but libvips now ships with a simple
bash completion script in `libvips-x.y.z/completions`, have a look at the
README in there for install notes. It knows how to complete operator names,
filenames, and required arguments, including enum values.

It's useful now, and we hope to improve it in the next version, perhaps by
expanding optional arguments, for example.

# Image format improvements

There have been quite a few improvements to file format support.

## **GIF** 

GIF save has a new `interlace` option, and the default save behaviour has
changed: for safety it now always recomputes the palette. If you want to
reuse the input palette, set the new `reuse` flag.

GIF load now handles truncated files much more gracefully.

## **HEIC/AVIF** 

The saver has a new `encoder` parameter you can use to select
the exact save codec library you want.

## **FITS** 

The FITS load and save operations have been rewritten. Many band
FITS images should load dramatically faster, and FITS save is much better at
handling duplicated header fields.

## Other

PNG load and save operations now support EXIF metadata.  Animated webp save
has been rewritten and should perform much better.  Saving as `.pnm` will
now pick the bext `p*m` subformat for you automatically.  The jp2k saver
now defaults to chroma subsample off for better compatibility, and writes
`jp2` images rather than a simple codestream.

Plus the usual range of small improvements and bugfixes. See the ChangeLog.
