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

![CICP PNG image](/API/8.19/cicp-car-small.png)

You can convert this terrible file to something more reasonable like this:

```console
$ vips copy cicp-car-small.png x.jpg
```

This will make a JPEG image. But the JPEG saver will automatically spot the
CICP tags on this image and generate a UltraHDR image with a synthetic ICC
profile based on the tag values.

This might now display as HDR, depending on your screen and browser:

![UltraHDR JPEG image](/API/8.19/uhdr-car-small.jpg)

You can also convert to AVIF, of course. Since AVIF supports CICP, this is
much simpler.

![CICP AVIF image](/API/8.19/cicp-car-small.avif)

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

- There are new [`qoiload`](/API/8.19/ctor.Image.qoiload.html) and
  [`qoisave`](/API/8.19/method.Image.qoisave.html) operations.

- The PNG load and save operations support animated PNG.

- [`jxlsave`](/API/8.19/method.Image.jxlsave.html) has a new `interlace`
  option.

- [`uhdrsave`](/API/8.19/method.Image.uhdrsave.html) has new options
  to control peak brightness and maximum content boost.

- [`dcrawload`](/API/8.19/ctor.Image.dcrawload.html) has better preview
  support and a `half-size` option

## Improvements to libvips operations

There have been some useful improvements to some basic libvips operations.

- [`thumbnail`](/API/8.19/ctor.Image.thumbnail.html) now has support for
  cropping by a specific point of interest, supports [`dcrawload`](
  /API/8.19/ctor.Image.dcrawload.html) thumbnails, and supports CICP HDR
  images.

- The [`vipsthumbnail`](/API/8.19/using-vipsthumbnail.html) utility supports
  the `@` modifier for sizing to a pixel count.

- [`composite`](/API/8.19/type_func.Image.composite.html) now supports the
  non-separable blending modes.

- [`project`](/API/8.19/method.Image.project.html) lets you set the combining
  mode.

- [`premultiply`](/API/8.19/method.Image.premultiply.html) and
  [`unpremultiply`](/API/8.19/method.Image.unpremultiply.html) now
  includes a fast 8-bit path.

## Improvements to the libvips core

The libvips core has seen some useful improvements.

- libvips is now C11.

- The old vips7 API is no longer built by default.

- New meson options let you disable features like man pages and CLI tools if
  you wish.

- `VIPS_UNLIMITED`, `--vips-unlimited`, [`vips_unlimited_get()`](
  /API/8.19/func.unlimited_get.html), [`vips_unlimited_set()`](
  /API/8.19/func.unlimited_set.html) let you disable DoS checks.

- A new [`VIPS_MEMCPY()`](/API/8.19/func.MEMCPY.html) macro gives a good
  speedup to small memory copies.

And the usual range of smaller improvements.
