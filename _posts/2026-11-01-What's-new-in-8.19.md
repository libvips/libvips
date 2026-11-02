---
title: What's new in libvips 8.19
---

Here's a summary of what's new in libvips 8.19. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

The headline features are support for CICP HDR images, the QOI image format, 

## CICP support

- add vips_CICP2scRGB [Starbix] [mertalev]
- jxlload, heifload, pngload: read CICP metadata [Starbix] [mertalev]
- jxlsave, heifsave, pngsave: write CICP metadata and pixel data
  [Starbix] [mertalev]
- jpegsave, uhdrsave: convert CICP image with HDR transfer to scRGB for HDR
  [Starbix] [mertalev]
- add percent_lum: find threshold for percent of pixels by BT.709 luminance [mertalev]
- add vips_scRGB2CICP [mertalev]
- add VIPS_UHDR_TO_SCRGB
- CICP: add chapter to docs
- colour: do not strip cicp or clli signaling [mertalev]
- XYZ2Lab: better handling of HDR values

## Improvements to libvips operations

- thumbnail: introduce cropping by a specific point of interest [pszemus]

- conversion: non-separable blending modes added [kstanikviacbs]
- reducev: auto-vectorise the vertical reduce for all band formats, up to ~3x faster [dloebl]
- add uchar options to premultiply and unpremultiply [jcupitt]
- project: add combine option [jcupitt]
- icc: fix black output when transforming float images [lancylot2004]
- thumbnail: add dcrawload thumbnail and preview support
- invert: prevent integer overflow for 32-bit signed TIFF input [lovell]
- affine: verify coordinates before adjusting margin [lovell]
- draw_line: add draw-point optional parameter [jcupitt]
- convi: sum using 128 bit integer, where available, before clipping [lovell]

- vipsthumbnail: add '@' modifier for size to pixel count
- thumbnail: pass missing `fail_on` arg to loaders [kleisauke]
- thumbnail: respect output profile and linear mode for cicp images [mertalev]

## Better file format support

As well as the RAW support above, the other file format operations have
seen some improvements:

- [`vips_pdfload()`](/API/current/ctor.Image.pdfload.html) has a new `"page-box"`
  argument which lets you control which of the various media boxes you'd like
  to load.

- pngload: support for EXIF data in zTXt chunks [pszemus]
- pngsave: add APNG support [felixbuenemann]
- pngload: add APNG support [felixbuenemann]
- pngload, pngsave: read and write cLLI metadata [gregbenz]
- pngsave: write iTXt chunks for text data (utf-8) [tonymarklove]

- jxlsave: add `interlace` option [mertalev]

- uhdrsave: add existing JPEG options for base image [lovell]
- uhdrsave: expose peak-brightness and max-content-boost parameters [dshatz]

- csvload: add maximum limit on column count [lovell]

- pdfload_buffer: only search the first few bytes in is_a [violetviolinist]

- heifload: allow mif2 and mif3 "brand" images eg. mini box [lovell]
- heifload, heifsave: preserve CLLI signaling [gregbenz]

- dcrawload: attach preview jpeg as metadata
- dcrawload: add half-size option

- add qoiload, qoisave [Snafuh]
- qoiload: ensure a custom source retains existing flags [Tan-JunWei]

- svgload: dpi= only scales DPI, scale= only scales dimensions [Czoczaj]

- magickload: scale and round Quantum values on unpack [kleisauke]

- tiffload: remove unreachable code due to bits_per_sample limit of 32 [lovell]
- tiffsave: disable tiling for LABQ JPEG images

- dzsave: reject imagename containing path separator [lovell]

## Improvements to the libvips core

The libvips core has seen some useful improvements:

- meson: options for building `man`, `po`, `tests`, `tools`; disable building
  `fuzz` by default [pszemus]
- meson: disable building `deprecated` by default [kleisauke]
- update toolchain requirement to C11 [kleisauke]

- add VIPS_UNLIMITED, --vips-unlimited, vips_unlimited_get()/_set() to
  disable DoS checks
- add VIPS_MEMCPY() [kleisauke]
- VipsRect: add g_autoptr cleanup
- cpp: add support for pointer args [kleisauke]
- cache: ensure entry invalidation uses mutex [Albert Ebb]
- foreign: trim excess bands to the largest size the saver supports [Socialpranker]

- add vips_image_get_blob_value()
- add vips_check_draw(), vips_image_copy_draw() [jcupitt]
- add vips_image_get_loop() [jcupitt]
- add vips_region_blend_over() [jcupitt]
