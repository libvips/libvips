---
title: What's new in libvips 8.19
---

Here's a summary of what's new in libvips 8.19. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog) if
you need more details.

The headline features are better HDR support, the [QOI image
format](https://en.wikipedia.org/wiki/QOI_(image_format)), and animated
PNGs. Plus the usual improvements to file format handling, libvips operations,
and the libvips core.

## Better HDR support

Thanks to great work by starbix and mertalev, libvips 8.19 and later now
loading and saving images with CICP tags from AVIF, JXL, and PNG images,
it supports loading and saving these images to UltraHDR formats like JPG
with automatic conversion of tags, and it supports save to ICC-only formats
with automatic profile generation. libvips also supports generating and
modifying CICP tags programmatically, including support for computing some
image properties, such as target illumination.

As an example, here's an HDR PNG image. It'll probably look very dark on your
screen, since almost no one supports this strange HDR image format:

![CICP PNG image](/assets/images/cicp-car-small.png)

You can convert this terrible file to something more reasonable like this:

```console
$ vips copy cicp-car-small.png x.jpg
```

This will make a JPEG image. But the JPEG saver will automatically spot the
CICP tags on this image and generate a UltraHDR image with a synthetic ICC
profile based on the tag values.

This might now display as HDR, depending on your screen and browser:

![UltraHDR JPEG image](/assets/images/uhdr-car-small.jpg)

You can also convert to AVIF, of course. Since AVIF supports CICP, this is
much simpler.

![CICP AVIF image](/assets/images/cicp-car-small.avif)

Again, the appearance will depend on your browser and display. On SDR
screens, these two versions of the original probably won't match well,
since the UltraHDR image has been tonemapped, whereas the AVIF will display
the SDR component of the CICP data.

These automatic conversions should work everywhere and in all libvips
bindings. You can also take charge of the HDR pipeline yourself if you
need more control, the [new chapter in the documentation for
CICP](https://www.libvips.org/API/8.19/cicp.html) has the details.

## Improvements to file format support

The other file format operations have seen some improvements:

- there are new `qoiload` and `qoisave` operations
- the PNG load and save operations support animated PNG
- `jxlsave` has a new `interlace` option
- `uhdrsave` has new parameters for the peak-brightness and max-content-boost 
  parameters
- `dcrawload` has better preview support and a half-size option

## Improvements to libvips operations

There have been some useful improvements to some basic libvips operations.

- `thumbnail` now has support for cropping by a specific point of interest,
  supports `dcrawload` thumbnails, and supports CICP HDR images
- the `vipsthumbnail` utility supports the `@` modifier for sizing to a pixel
  count
- `composite` now supports the non-separable blending modes 
- `project` lets you set the combining mode
- `premultiply` has a new fast 8 bit path

## Improvements to the libvips core

The libvips core has seen some useful improvements.

- libvips is now C11
- the old vips7 API is no longer built by default
- new meson options let you disable features like man pages and CLI tools if
  you wish
- `VIPS_UNLIMITED`, `--vips-unlimited`, `vips_unlimited_get()/_set()` let you
  disable DoS checks
- a new `VIPS_MEMCPY()` macro gives a good speedup to small memory copies

And the usual range of smaller improvements.
