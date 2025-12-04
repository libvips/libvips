---
title: What's new in libvips 8.18
---

libvips 8.18 should be out in a week or two, here's a summary of what's new.
Check the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

The headline features are support for UltraHDR, camera RAW images,
and Oklab colourspace.

## UltraHDR support

UltraHDR is a way of embedding a gainmap plus some extra metadata inside an
ordinary SDR image. An SDR display can just show the regular SDR image, but an
HDR display can extract the gainmap and use it to reconstruct a full HDR
image. Having a single image file that can display well on both SDR and HDR
devices is very valuable.

libvips 8.18 uses Google's [libultrahdr](https://github.com/google/libultrahdr)
for UltraHDR load and save. The current version of this library only
supports UltraHDR JPEG images; the next version is expected to add support
for a wider range of image formats.

There are two main paths for UltraHDR images in libvips: as an SDR image with a
separate gainmap, and as a full HDR image. The separate gainmap path is
relatively fast but you will sometimes need to update the gainmap during
processing. The full HDR path does not require gainmap updates, but can be
slower, and will usually lose the original image's tone mapping.

A new chapter in the libvips docuemtation introduces this new feature and
explains how to use it. As an example, you can use `vipsthumbnail` to resize
UltraHDR images. This command:

```
$ vipsthumbnail ultra-hdr.jpg --size 500
```

Makes this image:

[ultrahdr thumbnail](/assets/images/tn_ultra-hdr.jpg)

If you view that image on an HDR display and with a web browser that supports
UltraHDR images, the rocket exhaust should look very bright. It should also
look nicely tonemapped on an SDR display.

You can view the image metadata and see the extra information:

```
$ vipsheader -a tn_ultra-hdr.jpg 
tn_ultra-hdr.jpg: 500x281 uchar, 3 bands, srgb, uhdrload
width: 500
height: 281
bands: 3
format: uchar
coding: none
interpretation: srgb
xoffset: 0
yoffset: 0
xres: 1
yres: 1
filename: tn_ultra-hdr.jpg
vips-loader: uhdrload
exif-data: 186 bytes of binary data
resolution-unit: in
exif-ifd0-Orientation: 1 (Top-left, Short, 1 components, 2 bytes)
exif-ifd0-XResolution: 25400/1000 (25.400, Rational, 1 components, 8 bytes)
exif-ifd0-YResolution: 25400/1000 (25.400, Rational, 1 components, 8 bytes)
exif-ifd0-ResolutionUnit: 2 (Inch, Short, 1 components, 2 bytes)
exif-ifd0-YCbCrPositioning: 1 (Centred, Short, 1 components, 2 bytes)
exif-ifd2-ExifVersion: Exif Version 2.1 (Exif Version 2.1, Undefined, 4 components, 4 bytes)
exif-ifd2-ComponentsConfiguration: Y Cb Cr - (Y Cb Cr -, Undefined, 4 components, 4 bytes)
exif-ifd2-FlashpixVersion: FlashPix Version 1.0 (FlashPix Version 1.0, Undefined, 4 components, 4 bytes)
exif-ifd2-ColorSpace: 65535 (Uncalibrated, Short, 1 components, 2 bytes)
exif-ifd2-PixelXDimension: 500 (500, Long, 1 components, 4 bytes)
exif-ifd2-PixelYDimension: 281 (281, Long, 1 components, 4 bytes)
orientation: 1
icc-profile-data: 588 bytes of binary data
gainmap-data: 2065 bytes of binary data
gainmap-max-content-boost: 100 100 100 
gainmap-min-content-boost: 1 1 1 
gainmap-gamma: 1 1 1 
gainmap-offset-sdr: 0 0 0 
gainmap-offset-hdr: 0 0 0 
gainmap-hdr-capacity-min: 1
gainmap-hdr-capacity-max: 100
gainmap-use-base-cg: 1
```

## Camera RAW support

Thanks to @lxsameer, libvips 8.18 now has support for most camera RAW formats
by wrapping libraw. The new
[`vips_dcrawload()`](/API/8.18/method.Image.dcrawload.html) operator will be
used automatically to import images, so for example:

```
$ vipsthumbnail rotated.SRW --size 500
```

Makes this image

[dcrawload thumbnail](/assets/images/tn_rotated.jpg)


## Support for Oklab colourspace

Oklab and Oklch are a new colourspaces that are more linear than CIELAB
'76, faster to compute, and support HDR imaging. They have been added to 
CSS and are now supported by all major web browsers.





- add support for Oklab and Oklch colourspaces
- add vips_Oklab2XYZ(), vips_XYZ2Oklab()
- add vips_Oklab2Oklch(), vips_OKlch2Oklab()


## Improvements to operators

- add magickload_source: load from a source with imagemagick
- add vips__worker_exit(): enables fast threadpool shutdown
- larger mmap windows on 64-bit machines improve random access mode for many
  file formats
- pdfload: control region to be rendered via `page_box` [lovell]
- system: add "cache" argument
- add vips_image_get_tile_width(), vips_image_get_tile_height(): get tile
  cache geometry hints [jbaiter]
- add "bitdepth" to jxlsave
- add "path" option to vipsthumbnail, deprecate "output" option [zjturner]
- add "exact" to webpsave
- add vips_interpretation_bands()
- heifsave: add "tune" parameter
- require C++14 as a minimum standard [kleisauke]

To help compatibility, the old vips7 matrix multiply
function is now available as a vips8 operator,
[`matrixmultiply`](/API/current/method.Image.matrixmultiply.html).

We rewrote the old vips7 `remosaic` function for vips8 years
ago, but stupidly forgot to link it.  We've fixed this, and
[`remosaic`](/API/current/method.Image.remosaic.html)
is now proudly available. Similarly,
[`quadratic`](/API/current/method.Image.quadratic.html)
has been there for years, but never worked properly. It's been revised and
should now (finally) be useful.

The so-called [magic kernel](https://johncostella.com/magic) is [now
supported](/API/current/enum.Kernel.html#mks2021)
for image resize.

ICC import and transform now has an
[`auto`](/API/current/enum.Intent.html#auto) option
for rendering intent.

## Better file format support

File format support has been improved (again). Highlights this time are:

- [`gifsave`](/API/current/method.Image.gifsave.html)
  has a new `keep_duplicate_frames` option

- [`svgload`](/API/current/ctor.Image.svgload.html)
  has a new `stylesheet` option for custom CSS, and a `high_bitdepth` option
  for scRGB output.

- [`heifload`](/API/current/ctor.Image.heifload.html)
  has a new `unlimited` flag to remove all load limits, has better alpha
  channel detection, and better detection of truncated files.

- [`jp2kload`](/API/current/ctor.Image.jp2kload.html)
  has a new `oneshot` flag which can improve compatibility for older
  jp2k files.

- [`jxlsave`](/API/current/method.Image.jxlsave.html)
  has much lower memory use for large images.

- [`openslideload`](/API/current/ctor.Image.openslideload.html)
  now shares and reuses connections to the underlying file format library,
  improving speed.

- [`ppmload`](/API/current/ctor.Image.ppmload.html)
  has a new buffer variant for convenience.

- TIFF load and save has better error handling 

- A new "convert for save" system fixes a large number of minor bugs and
  inconsistencies in file format support.

## General improvements

There have been some smaller libvips additions and improvements too.

- The
  [`hough_line`](/API/current/method.Image.hough_line.html)
  operator has better scaling to Hough space.

- [`shrink`](/API/current/method.Image.shrink.html)
  is noticeably faster

- The operation cache is a lot more reliable.

- [`sink_screen`](/API/current/method.Image.sink_screen.html)
  has better scheduling and should render thumbnails much more quickly.

- The ICC operators are better at detecting and rejecting corrupt profiles.

Plus some even more minor bugfixes and improvements.
