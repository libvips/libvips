---
title: What's new in 8.11
---

libvips 8.11 is almost now out, so here's a quick overview of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Credit to Zeranoe, DarthSim, Projkt-James, afontenot, erdmann, kleisauke
and others for their great work on this release.

[Lunaphore](https://www.lunaphore.ch/) kindly sponsored the development of
the new JPEG2000 features, see below.

# Loadable modules for some image format loaders

- move openslide, libheif, poppler and magick to loadable modules [kleisauke]

# Experimental JPEG-XL support

- add JPEG-XL load and save

# Thread recycling

- new threading model has a single threadpool shared by all 
  pipelines [kleisauke]

# Full-colour text rendering

- add "rgba" flag to `vips_text()` to enable full colour text rendering

# JPEG2000 support

- add jp2kload, jp2ksave
- add jp2k compression to tiff load and save

# More loaders and savers moved to the new source / target framework

- add `vips_jpegload_source()` and `vips_svgload_source()` to public C API
- add `vips_source_g_input_stream_new()` to load images from a GInputStream
- add `openslideload_source()`, `vipsload_source()`, `vipssave_target()`
- vipsthumbnail supports stdin / stdout thumbnailing
- add `vips_fitsload_source()`, `vips_niftiload_source()`
- add source load support for pdfium

# C++ API improments

- integrate doxygen in build system to generate C++ API docs
- improve C++ API doc comments
- add VipsInterpolate and guint64 support to C++ API 
- add `VImage::new_from_memory_steal` [Zeranoe]

# New and improved image processing operations

- add "seed" param to perlin, worley and gaussnoise
- add hist path to rank for large windows on uchar images
- `hist_find` outputs a double histogram for large images [erdmann]
- add `black_point_compensation` flag for icc transforms
- better detection of invalid ICC profiles, better fallback paths

# Other

- better 8/16-bit choice for pngsave
- png and gif load note background colour as metadata [781545872]
- add GIF load with libnsgif
- add "premultiply" flag to tiffsave
- have a lock just for pdfium [DarthSim]
- avoid NaN in mapim [afontenot]
- fix ref leaks in mosaicing package
- run libvips leak test in CI 
- get pdfium load building again [Projkt-James]

As usual,
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.

