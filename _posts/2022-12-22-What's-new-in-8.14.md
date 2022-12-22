---
title: What's new in libvips 8.14
---

libvips 8.14 is almost done, so here's a summary of what's new. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

The headline features are the final switch to meson build system, a new
thread pool and thread recycling system, some useful speedups to TIFF load and
dzsave, and the usual small improveemnts to image format support. Details below!

We need to thank aksdb, dloebl, ewelot, tlsa, remicollet, DarthSim,
ejoebstl, lovell, shado23, kleisauke, and others for their great work on
this release.

Changes for this release:

# Build system changes

The previous release added a meson build system alongside the autotools build
system we'd used for decades. This release removed the autotools system
completely, and a lot of other old stuff too, so it's now meson all the way.

The README has some notes tyo help you get started if you need to build from
source, but the tldr is something like:

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
libvips has supported (via LittleCMS) conversion to and from CMYK images for a
long time.

In 8.14 we've added support for N-colour profiles. These printers add extra
colours, usually the complements of CMY, to expand the colour gamut available
and reduce dithering effects. The `icc_transform` set of operators now 
support rendering to and from N-colour device images in the obvious way.

The TIFF saver also knows how to read and write these CMYRGBK (for example)
files, and hopefully does it in a way that's compatible with PhotoShop.

We've added support for character as well as word wrapping to vips_text() with
the `wrap` parameter, added an `rgb` mode to `vips_openslideload()`, and
`vips_smartcrop()` now optionally returns the location of interest in
attention-based cropping.

# Improvements to the libvips core

## Faster threading

There has been a major change to the libvips core: we have a new threadpool
system. The new threadpool has several very useful new features:

1. Thread pools now resize dynamically. Each threadpool is able to tell how 
   busy their workers are, and are able to either size up or size down 
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
bit faster. Here's the previous release, libvips 8.13, running on a slide
image:





## Faster TIFF load

The previous libvips used libtiff to fetch decoded tiles from compressed 
TIFF files. This ran the decompressor inside the libtiff lock, so it was
single threaded.

In libvips 8.14, we've noved jpeg2000 and jpeg decompression outside the
libtiff lock so they now run multi-threaded. This gives a relly nice speedup.

Here's the previous 8.13 release:

And here's 8.14:


## bash completions

This won't appeal to many people, but libvips now ships with a simple
bash completion script in `libvips-x.y.z/completions`. It knows how to
complete operator names, filenames, and required arguments, including enum
values.

It's useful now, and perhaps it'll be improved in the next version.

# Image format improvements

There have been quite a few improvements to file format support.

- **GIF** Gif save has a new `interlace` option, and the default save
  behaviour has changed: it now always recomputes the palette. If you want to
  reuse the input palette, set the new `reuse` flag.

  Gif load now handles truncated files much more gracefully.

- **FITS** The FITS load and save operations have been fixed up. Many band
  FITS images should load dramatically faster, and FITS save is much better at
  handling duplicated header fields.

- **JP2K** The saver now defaults to chroms subsample off for compatibility,
  and writes `jp2` images rather than a simple codestream.

- **PNG** The PNG load and save operations now support EXIF metadata.

- **WebP** Animated webp save has been reqritten and should perform much
  better.

- **PNM** Saving as `.pnm` will now pick the bext `p*m` subformat for you
  automatically.

- **HEIC/AVIF** The saver has a new `encoder` parameter you can use to select
  the exact save codec library you want.

# Minor changes

And the usual range of small improvements and bugfixes. See the ChangeLog.
