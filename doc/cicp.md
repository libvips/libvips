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

The `thumbnail` operation knows about CICP tags and will use them
automatically for colour processing with the `linear` and `output-profile`
options.

### À la carte processing

You can also take over colour processing yourself by converting a native CICP
image to scRGB.

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
yres: 2.83398
filename: x.v
vips-loader: pngload
icc-profile-data: 4344 bytes of binary data
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

So the image has been converted to linear float, with the range 0-1 for black
to paper white. Values above 1.0 (the maximum for this image is 9.77)
represent HDR pixels.

The ICC profile and the CICP metadata are untouched. If you want to modify the
image and change the HDR presetation, you will probably need to update these.




This gainmap metadata is copied unmodified through any processing operations.
If you save an image with gainmap metadata to a JPEG file, libvips will do the
write with the [method@Image.uhdrsave] operation, embedding the gainmap and the
associated metadata in the output image.

Intermediate operations which change the image geometry will also need to
update the `"gainmap-data"` metadata item, the mechanisms for doing this are
described below. The other gainmap fields should probably not be changed
unless the intention is to alter the image appearance.

### High-level libvips operations

Two high-level libvips operations will automatically update the gainmap for
you during processing: [method@Image.dzsave] and [ctor@Image.thumbnail].

[method@Image.dzsave] always strips all metadata by default, so you'll need to
set `keep="gainmap"` to write the gainmap to the tiles. For example:

```
$ vips dzsave ultra-hdr.jpg x --keep gainmap
```

### À la carte processing

Other operations will NOT automatically update the gainmap for you. If you
call something like [method@Image.crop], an operation which changes the
image geometry, the gainmap and the image will no longer match. When
you save the cropped image, the gainmap is likely to be incorrect.

A helper function, [method@Image.get_gainmap], makes updating the gainmap
relatively easy: it returns a [class@Image] for the gainmap, and attaches
the image pointer as the metadata item `"gainmap"`. Once you have updated
the gainmap, you can overwrite this value.

For example, in C you could write

```C
VipsImage *image = ...;
VipsImage *out;
int left, top, width, height;
if (vips_crop(image, &out, left, top, width, height, NULL))
    return -1;

// also crop the gainmap, if there is one
VipsImage *gainmap;
if ((gainmap = vips_image_get_gainmap(out))) {
    // the gainmap can be smaller than the image, we must scale the
    // crop area
    double hscale = (double) gainmap->Xsize / image->Xsize;
    double vscale = (double) gainmap->Ysize / image->Ysize;

    VipsImage *new_gainmap;
    if (vips_crop(gainmap, &new_gainmap, left * hscale, top * vscale,
        width * hscale, height * vscale, NULL))
        return -1;
	g_object_unref(gainmap);

    // vips_image_set_image() modifies the image, so we need to make a
    // unique copy ... you can skip this step if you know your image is
    // already unique
    VipsImage *new_out;
    if (vips_copy(out, &new_out, NULL)) {
	    g_object_unref(new_gainmap);
        return -1;
    }
    g_object_unref(out);
    out = new_out;

    // update the gainmap
    vips_image_set_image(out, "gainmap", new_gainmap);

    g_object_unref(new_gainmap);
}
```

Or with ruby-vips:

```ruby
def crop_image_and_gainmap(image, left, top, width, height)
  image = image.crop left, top, width, height
  gainmap = image.get_gainmap
  unless gainmap.nil?
    hscale = gainmap.width / image.width
    vscale = gainmap.height / image.height
    new_gainmap = gainmap.crop left * hscale, top * vscale, width * hscale, height * vscale
    image = image.mutate do |mutable|
      mutable.set_type! Vips::IMAGE_TYPE, "gainmap", new_gainmap
    end
  end

  image
end
```

### Performance and quality considerations

Doing gainmap processing explicitly like this has two big advantages:
first, you have exact control over this processing, so you can make sure
only the gainmap transformations that are strictly necessary take place.
Secondly, since you supply the gainmap to the UltraHDR save, you can also
be certain any user tone mapping is preserved.

The disadvantage is the extra development work necessary. The second UltraHDR
path in libvips avoids this problem.

## Full HDR processing

You can transform an UltraHDR SDR plus gainmap image to full HDR with
[method@Image.uhdr2scRGB]. This will compute an scRGB image: a three-band
float with sRGB primaries, black to white as linear 0-1, and out of range
values used to represent HDR.

For example:

```
$ vips uhdr2scRGB ultra-hdr.jpg x.v
$ vipsheader x.v
x.v: 3840x2160 float, 3 bands, scrgb, uhdrload
$ vips max x.v
15.210938
```

If you save an scRGB image as JPEG, it will be automatically written as
UltraJPEG. Any associated gainmap is thrown away and basic tonemapping
performed to make a new gainmap for SDR display.

Full HDR processing with scRGB is simple, but potentially slower than the
separate gainmap path, and will not preserve any user tone map.

