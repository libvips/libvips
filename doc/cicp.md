Title: Using > Processing CICP images

[CICP is a relatively new](https://en.wikipedia.org/wiki/Coding-independent_code_points)
way of tagging an image with information about how colour values should be
displayed. It serves roughly the same purpose as an ICC profile, but is
very small, simple, and is designed for HDR.

libvips supports loading and saving images with CICP tags from AVIF, JXL,
and PNG images, it supports loading and saving these images to UltraHDR
formats like JPG with automatic conversion of tags, and it supports save to
ICC-only formats with automatic profile generation. libvips also supports
generating and mofifying CICP tags programmatically, including support for
computing some image properties, such as target illumination.

As with other colour tagging systems, like ICC and UtrahDR, there are two main
paths for CICP images. You can leave them as 16-bit insigned integer with
CICP tags and rely on automatic conversion by savers, or you can convert
them to full HDR images in scRGB space and do you own colour handling.
Doing your own handling will usually be slower, but give more control.

## Native numeric format with CICP tagging

CICP images are 16-bit unsigned integers, with extra metadata for colour
interpretation.

### Load

Images are left in native CICP format by loaders.

For example:

```
$ vipsheader -a cicp-car.png
cicp-car.png: 3840x2160 ushort, 3 bands, rgb16, pngload
width: 3840
height: 2160
bands: 3
format: ushort
coding: none
interpretation: rgb16
xoffset: 0
yoffset: 0
xres: 2.834
yres: 2.834
filename: cicp-car.png
vips-loader: pngload
icc-profile-data: 4344 bytes of binary data
cicp-colour-primaries: 9
cicp-transfer-characteristics: 16
cicp-matrix-coefficients: 0
cicp-full-range-flag: 1
clli-max-content-light-level: 769
clli-max-frame-average-light-level: 75
png-comment-0-Software: HDRFrame
xmp-data: 563 bytes of binary data
png-comment-2-HDRFrame.CaptureMode: window
png-comment-3-HDRFrame.SourceBackend: wgc
png-comment-4-HDRFrame.SourceHDR: true
bits-per-sample: 16
```

As well as the four pieces of CICP metadata, two extra tags give the peak and
average luminance for the image. These help displays map general image
pixel values to values appropriate for this specific display.

### Save

When you save an image like this in another format, the saver will attempt to
generate the best image it can automatically.

For example:

```
$ vips copy cicp-car.png x.jpg
$ vipsheader -a x.jpg
x.jpg: 3840x2160 uchar, 3 bands, srgb, uhdrload
width: 3840
height: 2160
bands: 3
format: uchar
coding: none
interpretation: srgb
xoffset: 0
yoffset: 0
xres: 2.83398
yres: 2.83398
filename: x.jpg
vips-loader: uhdrload
exif-data: 186 bytes of binary data
resolution-unit: in
exif-ifd0-Orientation: 1 (Top-left, Short, 1 components, 2 bytes)
exif-ifd0-XResolution: 71983/1000 (71.983, Rational, 1 components, 8 bytes)
exif-ifd0-YResolution: 71983/1000 (71.983, Rational, 1 components, 8 bytes)
exif-ifd0-ResolutionUnit: 2 (Inch, Short, 1 components, 2 bytes)
exif-ifd0-YCbCrPositioning: 1 (Centred, Short, 1 components, 2 bytes)
exif-ifd2-ExifVersion: Exif Version 2.1 (Exif Version 2.1, Undefined, 4 components, 4 bytes)
exif-ifd2-ComponentsConfiguration: Y Cb Cr - (Y Cb Cr -, Undefined, 4 components, 4 bytes)
exif-ifd2-FlashpixVersion: FlashPix Version 1.0 (FlashPix Version 1.0, Undefined, 4 components, 4 bytes)
exif-ifd2-ColorSpace: 65535 (Uncalibrated, Short, 1 components, 2 bytes)
exif-ifd2-PixelXDimension: 3840 (3840, Long, 1 components, 4 bytes)
exif-ifd2-PixelYDimension: 2160 (2160, Long, 1 components, 4 bytes)
orientation: 1
icc-profile-data: 600 bytes of binary data
gainmap-data: 42867 bytes of binary data
gainmap-max-content-boost: 49.2611 49.2611 49.2611
gainmap-min-content-boost: 1 1 1
gainmap-gamma: 1 1 1
gainmap-offset-sdr: 0 0 0
gainmap-offset-hdr: 0 0 0
gainmap-hdr-capacity-min: 1
gainmap-hdr-capacity-max: 49.2611
gainmap-use-base-cg: 1
gainmap-scale-factor: 2
```

The JPEG saver has seen the CICP tags and generated an UltraHDR image
automatically using libultrahdr, including the gainmap and the ICC profile.
The profile is derived from the CICP tags and does not use the profile on
the source PNG, since if an ICC profile and CICP metadata are both present,
the CICP data is preferred.

### High-level libvips operations

The [method@Image.thumbnail] operation knows about CICP tags and will use them
automatically for colour processing with the `linear` and `output-profile`
options.

### À la carte processing

You can also take over colour processing yourself by converting a native CICP
image to scRGB using [method@Image.CICP2scRGB].

For example:

```
$ vips CICP2scRGB cicp-car.png x.v
$ vipsheader -a x.v
x.v: 3840x2160 float, 3 bands, scrgb, pngload
width: 3840
height: 2160
bands: 3
format: float
coding: none
interpretation: scrgb
xoffset: 0
yoffset: 0
xres: 2.83398
yres: 2.83398G
filename: x.v
vips-loader: pngload
icc-profile-data: 4344 bytes of binary data
cicp-colour-primaries: 9
cicp-transfer-characteristics: 16
cicp-matrix-coefficients: 0
cicp-full-range-flag: 1
clli-max-content-light-level: 769
clli-max-frame-average-light-level: 75
png-comment-0-Software: HDRFrame
xmp-data: 563 bytes of binary data
png-comment-2-HDRFrame.CaptureMode: window
png-comment-3-HDRFrame.SourceBackend: wgc
png-comment-4-HDRFrame.SourceHDR: true
bits-per-sample: 16
vips-sequential: 1
exif-data: 186 bytes of binary data
resolution-unit: in
exif-ifd0-Orientation: 1 (Top-left, Short, 1 components, 2 bytes)
exif-ifd0-XResolution: 71983/1000 (71.983, Rational, 1 components, 8 bytes)
exif-ifd0-YResolution: 71983/1000 (71.983, Rational, 1 components, 8 bytes)
exif-ifd0-ResolutionUnit: 2 (Inch, Short, 1 components, 2 bytes)
exif-ifd0-YCbCrPositioning: 1 (Centred, Short, 1 components, 2 bytes)
exif-ifd2-ExifVersion: Exif Version 2.1 (Exif Version 2.1, Undefined, 4 components, 4 bytes)
exif-ifd2-ComponentsConfiguration: Y Cb Cr - (Y Cb Cr -, Undefined, 4 components, 4 bytes)
exif-ifd2-FlashpixVersion: FlashPix Version 1.0 (FlashPix Version 1.0, Undefined, 4 components, 4 bytes)
exif-ifd2-ColorSpace: 65535 (Uncalibrated, Short, 1 components, 2 bytes)
exif-ifd2-PixelXDimension: 3840 (3840, Long, 1 components, 4 bytes)
exif-ifd2-PixelYDimension: 2160 (2160, Long, 1 components, 4 bytes)
orientation: 1
$ vips max x.v
9.773916
$ vips min x.v
0.000194
```

So the image has been converted to linear float, with the range 0-1 for
black to paper white. Values above 1.0 (the maximum for this image is 9.77,
for example) represent HDR pixels.

The ICC profile and the CICP metadata are untouched. If you modify the image
and want to change the HDR presetation, you will need to update these using
[method@Image.get_double] and friends.

You can use [method@Image.percent_lum] to compute `clli-max-content-light-level`
and `clli-max-frame-average-light-level` efficiently.

You can convert in the other direction with [method@Image.scRGB2CICP].

