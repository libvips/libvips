---
title: What's new in libvips 8.13
---

libvips 8.13 is almost done, so here's a summary of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Many thanks to remicollet, DarthSim, GavinJoyce, tintou, lovell, shado23,
dloebl, tlsa, kleisauke and others for their great work on
this release.

# New [meson](https://mesonbuild.com) build system

libvips has been using [GNU
autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)
as its build system since the 1990s. It's worked well for us, but the
world is moving on and a new generation of build systems are trying hard
to displace it.

We've settled on [meson](https://mesonbuild.com) and tintou has very
generously done all the work. The old autotools system is still there for this
release, but it will be removed for 8.14 and meson will the only one we
support.

The new build cheatsheet is:

```
cd libvips-x.y.x
meson setup build-dir --prefix=/aaa/bbb/ccc
cd build-dir
meson compile
meson test
meson install
```

The new system is a *lot* faster. On this PC, the autotools build system used 
to take 17s to configure and 6s to build libvips. Meson takes 2.8s to
configure and ninja takes 4.6s to build. A four times speedup is very welcome.

The [libvips
README](https://github.com/libvips/libvips/blob/master/README.md#building-from-source)
has some more notes.

**Maybe move this down the running order? Only devs will care**

# Blocking of unfuzzed loaders 

libvips support many image format libraries. Some of these are well tested
against malicious input files, but some are not.

If you were developing a web service that used libvips to handle untrusted
image files, our advice used to be to build your own libvips binary that
only had support for the file types you wanted to handle (this is what
projects like [sharp](https://sharp.pixelplumbing.com) do).  This was safe,
but also hard work --- it could make deployment significantly more complex
for some users.

libvips 8.13 has a new feature which can block untrusted operations at
runtime, and at a very low level. This means you can use any libvips binary
and be confident that any unsafe code is not being exposed to internet data.

If the environment variable `VIPS_BLOCK_UNTRUSTED` is set, then any operation
that we've tagged as untrusted will be prevented from running. This should
be very simple to add to existing projects.

There's also an API which gives much finer control. See
[`vips_operation_block_untrusted_set()`](link) and
[`vips_operation_block_set()`](link), We'll add these operations to the
various libvips bindings.

# Improved GIF support

GIF handling has been reworked again, and should now produce smaller files
(sometimes much smaller) with lower CPU and memory load.

Here's a benchmark with a short video clip:

```
# libvips 8.12
$ /usr/bin/time -f %M:%e vipsthumbnail 3198.gif[n=-1] -o vips-12.gif --size 224
57764:3.96
# libvips 8.13
$ /usr/bin/time -f %M:%e vipsthumbnail 3198.gif[n=-1] -o vips-13.gif --size 224
57344:0.62
$ ls -l vips-12.gif vips-13.gif
-rw-r--r-- 1 john john 3441032 Jun  8 16:34 vips-12.gif
-rw-r--r-- 1 john john 2487189 Jun  8 16:25 vips-13.gif
```

So about 7x faster and 30% smaller.

There's a good improvement against imagemagick too:

```
$ /usr/bin/time -f %M:%e convert 3198.gif -resize 75% im.gif
200796:6.44
$ ls -l im.gif vips-13.gif 
-rw-rw-r-- 1 john john 3176859 Jun  8 16:26 im.gif
```

On this task, compared to imagemagick6, libvips is around 10x faster,
needs 4x less memory, makes GIFs which are 20% smaller, and produces higher
quality output.

The new GIF saver has quite a few options to control output, take a look at
[the docs](link).

**Should we remove some of the gif save options? Maybe just set sane values
for interframe-maxerror and interpalette-maxerror**

**Perhaps explain reoptimise and the strategy for local ctables?**

# Image resize quality improvements

Kleis has spent a long time making a series of quality improvements to the
image resize code. It should be no slower, but a series of edge cases have
been identified and resolved.

**add some more stuff**

# File format support improvements

There have been the usual range of improvements to file format support.
Briefly:

### `tiffsave` and `dzsave` to target

You can now write DeepZoom and TIFF images to the new libvips target API. This
means you can write these formats (for example) to pipes or even perhaps S3
buckets with no need for intermediate files.

There are some complications due to the way these formats work, and you can
need up to 30% of the image size in memory for extra buffering. But at least
it's possible now.

### `libspng` save

If possible, libvips will now use the
[`libspng`](https://github.com/randy408/libspng) library for PNG write as
well as PNG read.  This can produce a useful increase in PNG speed.

### HEIC and AVIF

These now support HDR images, and the loader has a new option to disable to
DoS attack limits.

### Other loader improvements

- add `password` option to `pdfload`, fix byte ordering of `background`
- add `mixed` to `webpsave` [dloebl]
- add `bitdepth` to `magicksave` [dloebl]
- `jp2kload` load left-justifies bitdepth
- add `fail-on` to `thumbnail`

# General minor improvements

- add `extend`, `background` and `premultiplied` to `vips_mapim()` to fix edge
  antialiasing [GavinJoyce]
- improve the pixel RNG for the noise operators
- add support for regions in C++ API [shado23]
- improve introspection annotations [tintou]

