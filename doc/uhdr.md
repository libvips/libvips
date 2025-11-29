Title: Using > Processing UltraHDR images

libvips can process HDR images encoded with
[UltraHDR](https://en.wikipedia.org/wiki/Ultra_HDR). These are ordinary
SDR images, but with a gainmap embedded within them -- SDR displays will
just show the regular SDR image, but for an HDR display, the extra gainmap
can be used as an exponent to recover the full HDR range. This ability to show
the same file in good quality on both SDR and HDR displays makes the format
very useful.

Google's [libultrahdr](https://github.com/google/libultrahdr) is used to
implement UltraHDR load and save. The current version of this library only
supports UltraHDR JPEG images; the next version is expected to add
support for a wider range of image formats.

There are two main paths for UltraHDR images in libvips: as an image with a
separate gainmap, and as a full HDR image. The separate gainmap path is
relatively fast but you will sometimes need to update the gainmap during
processing. The full HDR path does not require gainmap updates, but can be
slower, and will usually lose the original image's tone mapping.

## UltraHDR with an separate gainmap

libvips will detect JPEG images with an embedded gainmap and automatically
invoke the [ctor@Image.uhdrload] operation to load them. This operation
attaches the gainmap (a small JPEG-compressed image) as the `"gainmap-data"`
metadata item, plus some other gainmap tags.

### Load and save

For example:

```
$ vipsheader -a ultra-hdr.jpg
ultra-hdr.jpg: 3840x2160 uchar, 3 bands, srgb, uhdrload
width: 3840
height: 2160
bands: 3
format: uchar
coding: none
interpretation: srgb
xoffset: 0
yoffset: 0
xres: 1
yres: 1
filename: ultra-hdr.jpg
vips-loader: uhdrload
icc-profile-data: 588 bytes of binary data
gainmap-data: 31738 bytes of binary data
gainmap-max-content-boost: 100 100 100
gainmap-min-content-boost: 1 1 1
gainmap-gamma: 1 1 1
gainmap-offset-sdr: 0 0 0
gainmap-offset-hdr: 0 0 0
gainmap-hdr-capacity-min: 1
gainmap-hdr-capacity-max: 100
gainmap-use-base-cg: 1
```

The gainmap metadata is copied unmodified through any processing operations.
If you save an image with gainmap metadata to a JPEG file, libvips will do the
write with the [method@Image.uhdrsave] operation, embedding the gainmap and the
associated metadata in the output image.

### High-level libvips operations

Two high-level libvips operations will automatically update the gainmap for
you during processing: [method@Image.dzsave] and [ctor@Image.thumbnail].

[method@Image.dzsave] always strips all metadata by default, so you'll need to
set `keep="gainmap"` to write the gainmap to the tiles. For example:

```
$ vips dzsave ultra-hdr.jpg x --keep gainmap
```

### A la carte processing

Other operations will NOT update the gainmap for you automatically. If you
call something like [method@Image.crop], an operation which changes the
image geometry, the gainmap and the image will no longer match up. When
you save the cropped image, the gainmap is very likely to be incorrect.

Any time you change the image geometry, you must also update the gainmap. A
helper function, [method@Image.get_gainmap], makes this relatively easy: it
returns a [class@Image] for the gainmap, and attaches the image pointer as
the metadata item `"gainmap"`. Once you have updated the gainmap, you can
overwrite this value.

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
    // gainmap is not a reference, just a pointer to the ref held by
    // out.gainmap

    // the gainmap can be smaller than the image, we must scale the
    // crop area
    double hscale = (double) gainmap->Xsize / image->Xsize;
    double vscale = (double) gainmap->Ysize / image->Ysize;

    VipsImage *x;
    if (vips_crop(gainmap, &x, left * hscale, top * vscale,
        width * hscale, height * vscale, NULL))
        return -1;

    // update the gainmap
    vips_image_set_image(out, "gainmap", x);

    g_object_unref(x);
}
```

### Performance and quality considerations

Doing the gainmap processing explicitly like this has two big advantages:
first, you have control over this processing, so you can make sure only the
gainmap transformations that are strictly necessary take place. Secondly,
since you supply the gainmap to the UltraHDR save, you can also be certain any
user tone mapping is preserved.

The disadvantage is the extra development work necessary, The second UltraHDR
path in libvips avoids this problem.

## Full HDR processing

You can also load UltraHDR images as full HDR by setting the `hdr` flag. This
will load the image as scRGB -- a three-band float with sRGB primaries, black
to white as linear 0-1, and out of range values used to represent HDR.

For example:

```
$ vips max ultra-hdr.jpg[hdr]
15.210938
```

The `hdr` flag means float HDR load, and [method@Image.max] finds an scRGB
value of 15.2, well outside the usual 0-1 range of scRGB.

The gainmap metadata is still there:

```
$ vipsheader -a ultra-hdr.jpg[hdr]
ultra-hdr.jpg: 3840x2160 float, 3 bands, scrgb, uhdrload
width: 3840
height: 2160
bands: 3
format: float
coding: none
interpretation: scrgb
xoffset: 0
yoffset: 0
xres: 1
yres: 1
filename: ultra-hdr.jpg
vips-loader: uhdrload
icc-profile-data: 588 bytes of binary data
gainmap-data: 31738 bytes of binary data
gainmap-max-content-boost: 100 100 100
gainmap-min-content-boost: 1 1 1
gainmap-gamma: 1 1 1
gainmap-offset-sdr: 0 0 0
gainmap-offset-hdr: 0 0 0
gainmap-hdr-capacity-min: 1
gainmap-hdr-capacity-max: 100
gainmap-use-base-cg: 1
```

If you save a scRGB image as JPEG, it will be automatically written as
UltraJPEG. A simple gainmap is generated automatically.

Full HDR processing scRGB is simple, but potentially slower than the separate
gainmap path, and will not preserve any user tone map.

## Full HDR from separate gainmap

You can use [method@Image.uhdr2scRGB] to convert a SDR + gainmap image into a
full HDR scRGB image.


# TODO

- add scRGB2uhdr .. inverse of uhdr2scRGB? only works if there's a gainmap on
  the scRGB image
- don't use libuhdr linear import, just call uhdr2scRGB on result
- call uhdr2scRGB automatically from sRGB2scRGB
- uhdr should be a supported colourspace? not clear how this would interact
  with nclx, best to leave it
- verify that uhdrsave will only use `gainmap-data` if `gainmap` is missing
- saving scRGB as uhdr always recomputes the gainmap, is this the best
  behaviour?


