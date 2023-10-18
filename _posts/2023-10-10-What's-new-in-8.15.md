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

# Performance improvements

Traditionally, libvips relied on [liborc's runtime compiler](
https://gitlab.freedesktop.org/gstreamer/orc)
to dynamically generate optimised SIMD/vector code specifically for the target
architecture. However, maintaining this code proved challenging, and it didn't
generalize to architectures like [WebAssembly](
/2020/09/01/libvips-for-webassembly.html#performance).
Additionally, it lacked support for newer instruction sets like AVX2 and
AVX-512, and the vector paths of liborc didn't match the precision of the C
paths.

In 8.15, we've optimised various operations by leveraging [Highway](
https://github.com/google/highway), a C++ library with carefully-chosen
functions that map well to CPU instructions without extensive compiler
transformations. Highway supports five architectures, allowing our code to
target various instruction sets, including those with 'scalable' vectors
(size unknown at compile time). At runtime, dynamic dispatch selects the best
available implementation based on the processor's capabilities, ensuring
optimal performance. While Highway is our preferred choice, the liborc paths
remain available as a fallback whenever Highway is unavailable.

Additionally, for x86/x86-64 targets, a couple of functions are now marked
with the `target_clones` attribute to improve performance on AVX CPUs by ~10%.

An improvement to the shrink operators has allowed a dramatic speedup in
edge cases where there was upstream coordinate transformation. Performance
should now be more predictable in these cases.

# Image load and save improvements

There are two improvements to all loaders and savers. First, you can pass a
`revalidate` flag to all loaders which will make them bypass the libvips cache
and refetch the image from the source. This is useful if you are loading a file
where the contents might change.

Secondly, we've deprecated the `strip` option to savers and added a new `keep`
option which you can use to select what classes of metadata item you'd like to
*not* remove. For example:

```
$ vips copy k2.tif x.jpg[keep=icc:exif]
```

Will copy a JPEG image, keep any ICC profile and EXIF metadata, but delete
everything else, such as XMP and IPTC. Use `keep=none` to remove everything.
This new colon syntax for flag options works everywhere, including in language
bindings.

We've added a new `bitdepth` metadata item which all loaders and savers
now support, and deprecated the old `palette-bit-depth` and `heif-bitdepth`
fields.

## Better `tiffsave`

libvips used to rely on libtiff to manage write of compressed tiles. This
meant that the selected compression library (libjpeg, perhaps) would run
inside the libtiff lock, and compression was therefore single-threaded.

In libvips 8.15, we've taken over control of JPEG and JPEG2000 compression
and we now do this ourselves in parallel, leaving only the raw tile
write to libtiff.

When making a JPEG-compressed TIFF with libvips 8.14 I see:

```
$ time vips copy CMU-1.svs[rgb] x.tif[compression=jpeg,tile,pyramid]
real	0m11.732s
user	1m8.123s
sys	0m5.810s
```

But with 8.15 it's now:

```
$ time vips copy CMU-1.svs[rgb] x.tif[compression=jpeg,tile,pyramid]
real	0m5.332s
user	1m2.410s
sys	0m7.543s
```

More than twice as fast.

We've also added support for load and save of 16-bit float TIFFs, and improved
the compatibility of 32-bit float TIFFs.

## Better `dzsave`

libvips used to save each tile in `dzsave` by building and executing a complete
libvips pipeline. With small tiles, the setup and teardown cost
was often a significant part of the runtime, and this limited speed.

With libvips 8.15 we've added a direct path for JPEG tiles (the default case)
which avoids this overhead.

With libvips 8.14 I saw:

```
$ time vips dzsave CMU-1.svs[rgb] x
real	0m14.435s
user	1m26.434s
sys	0m50.474s
```

With 8.15 it's now:

```
$ time vips dzsave CMU-1.svs[rgb] x
real	0m5.586s
user	1m4.462s
sys	0m21.581s
```

Nearly 3x faster. There's a new `--Q` flag to set the Q factor for direct JPEG
tile save.

We've made another improvement to `dzsave`: it now uses a better ZIP write
library, `libarchive`, which should improve portability.

# General improvements

* PDF loading with PDFium now includes support for PDF forms, making it
  capable of rendering user-provided input in checkboxes and text fields.
* We've added two new edge detectors,
  [`vips_scharr()`](/API/current/libvips-convolution.html#vips-scharr) and
  [`vips_prewitt()`](/API/current/libvips-convolution.html#vips-prewitt),
  and improved the accuracy of
  [`vips_sobel()`](/API/current/libvips-convolution.html#vips-sobel).  
* [`vips_find_trim()`](/API/current/libvips-arithmetic.html#vips-find-trim)
  features a `line_art` option.
* GIF load now sets `interlaced=1` for interlaced GIF images.  
* Improved C++ binding, taking advantage of C++11 features.  
* The built-in ICC profiles are replaced with ICC v4 variants.
