---
title: What's new in libvips 8.15
---

libvips 8.15 is almost done, so here's a summary of what's new. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

The headline features are SIMD optimisations with Highway, some useful
speedups to `dzsave` and TIFF save, metadata improvements, and the usual
small improvements to image format support. Details below!

We need to thank lovell, kleisauke, miltoncandelero, MathemanFlo,
donghuikugou, jcupitt, DarthSim, shado23, a3mar, and others for their great
work on this release.

Changes for this release:

# SIMD optimisations

Traditionally, libvips relied on [liborc's runtime compiler](
https://gitlab.freedesktop.org/gstreamer/orc)
to dynamically generate optimised SIMD/vector code specifically for the target
architecture. However, maintaining this code proved challenging, and it didn't
generalize to other architectures (such as [WebAssembly](
/2020/09/01/libvips-for-webassembly.html#performance)).
Additionally, it lacked support for newer instruction sets (like AVX2 and
AVX-512), and the vector paths of liborc didn't match the precision of the C
paths.

In 8.15, we've optimised various operations by leveraging [Highway](
https://github.com/google/highway), a C++ library with carefully-chosen
functions that map well to CPU instructions without extensive compiler
transformations. Highway supports five architectures; allowing our application
code to target various instruction sets, including those with 'scalable'
vectors (size unknown at compile time). At runtime, dynamic dispatch selects
the best available implementation based on the processor's capabilities,
ensuring optimal performance. While Highway is our preferred choice, the
liborc paths remain available as a fallback whenever Highway is unavailable.

Additionally, for x86/x86-64 targets, a couple of functions are now marked
with the `target_clones` attribute to improve performance on AVX CPUs by ~10%.

> - add support for SIMD via Highway [kleisauke]
> - add support for target_clones attribute [lovell]
>   * use with (un)premultiply for ~10% perf gain on AVX CPUs
>   * use with XYZ to LAB colourspace conversion for ~10% perf gain on AVX CPUs

# Faster `dzsave` and `tiffsave`

> - add direct mode to dzsave [jcupitt]
> - threaded write in tiffsave for tiled JPEG and JPEG2000 [jcupitt]
> - remove libgsf dependency in favor of libarchive [kleisauke]

# Metadata improvements

> - add "keep" flag to foreign savers, deprecate "strip" [a3mar]
> - add VIPS_META_BITS_PER_SAMPLE metadata, deprecate the
>    "palette-bit-depth" and "heif-bitdepth" meta fields [MathemanFlo]

# Image format improvements

There have been a couple improvements to file format support.

## **GIF**

GIF load now sets `interlaced=1` for interlaced GIF images.

> - set "interlaced=1" for interlaced GIF images [kleisauke]

## **PDF**

PDF loading with PDFium now includes support for PDF forms, making it
capable of rendering user-provided input in checkboxes and text fields.

> - add support for forms in pdfium loader [kleisauke]

## **TIFF**

TIFF load now supports 16-bit float TIFFs.

> - add support for 16-bit float TIFFs [DarthSim]

# General minor improvements

* [`vips_find_trim()`](/API/current/libvips-arithmetic.html#vips-find-trim)
  features a `line_art` option.
* Improved C++ binding, taking advantage of C++11 features.
* Foreign loaders includes support for the `revalidate` option.
* The built-in ICC profiles are replaced with ICC v4 variants.
* Improved performance of [`vips_shrinkh()`](
  /API/current/libvips-resample.html#vips-shrinkh) and [`vips_shrinkv()`](
  /API/current/libvips-resample.html#vips-shrinkv) for small shrinks.
* scRGB images uses an alpha range of 0.0 - 1.0.
* Added [`vips_scharr()`](/API/current/libvips-convolution.html#vips-scharr) 
  and [`vips_prewitt()`](/API/current/libvips-convolution.html#vips-prewitt)
  edge-detectors.
* [`vips_sobel()`](/API/current/libvips-convolution.html#vips-sobel) is a more
  accurate for non-uchar images.

> - add @line_art to find_trim [miltoncandelero]
> - improve C++ binding [MathemanFlo]
>   * add `inplace()` / `VImage::new_from_memory_copy()`
>   * add overloads for `draw_*()` / `VImage::thumbnail_buffer()`
> - require C++11 as a minimum standard [kleisauke]
> - add "revalidate" to foreign loaders [jcupitt]
> - swap built-in profiles with ICC v4 variants [kleisauke]
> - better chunking for small shrinks [jcupitt]
> - use alpha range of 0.0 - 1.0 for scRGB images [DarthSim]
> - add "prewitt" and "scharr" edge detectors, "sobel" is more accurate for
>   non-uchar formats [jcupitt]

Plus the usual range of small improvements and bugfixes. See the ChangeLog.

> - add fast path to extract_band and bandjoin for uchar images [lovell]
> - reduce `vips_sharpen` max `sigma` to 10 [lovell]
> - inline scRGB to XYZ colourspace conversion, ~2x faster [lovell]
> - allow negative line spacing in text [donghuikugou]
> - add `premultiplied` option to smartcrop [lovell]
> - add vips_thread_execute() to the public API [jcupitt]
