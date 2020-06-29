---
title: What's new in 8.10
---

libvips 8.10 is now done, so here's a quick overview of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Credit to regisrob, rgluskin, akemrir, alon-ne, Elad-Laufer, jclavoie-jive,
petoor, UweOhse, kleisauke, MathemanFlo and others for their great work on
this release. 

[Lunaphore](https://www.lunaphore.ch/) kindly sponsored the development of
the improved Bioformats pyramid compatibility, see below.

# Image resize

We've put quite a bit of time into improving image resize.

Thanks to hard work by kleisauke, libvips downsize is now fully symmetrical.
This means that whatever orientation your image has, downsizing will produce
an identical result. This ought to eliminate the pizel shifts you used to be
able to see between libvips output and the output of other resize software.

We've also revised kernel computation and it should be more accurate than
before. A problem with upsizing images containing transparent elements has also
been fixed.

`smartcrop` now has an `all` mode, so you can disable cropping, and libvips now
handles all the EXIF image orientations for all formats.

# libspng

libvips now has support for [libspng](https://libspng.org/), a new PNG
library which is simpler, faster and more secure than the usual libpng.

You can expect roughly a 25% speedup for PNG load. For now, save is still
via libpng.

# Pyramids

The libvips pyramid builders have seen some improvements too. 

Thanks to sponsorship from Lunaphore, the TIFF pyramid reader and writer
now supports SUBIFD tags. This means libvips can now read and write
Bioformats-style image pyramids.

libvips used to only write TIFF pyramids like this:

![Old-style libvips TIFF pyramids]({{ site.baseurl }}/assets/images/old-pyr.png)

Each smaller version of the image is stored in a subsequent page in the TIFF
file. This is easy and convenient, and how most TIFF pyramids writers work, but
it means that many-page images can't also have pyramids, since that dimension is
already used to represent pyramid layers.

Bioformats OME is a varient of TIFF used in technical microscopy. OME-TIFF 
images can have many, many bands (RGB, flourescence, volume, and so on),
and these bands can differ in size. This makes them difficult to store in 
regular TIFF files.

To get around this, OME-TIFF makes all images stored in the TIFF file one
band only, and uses the pages dimension to represent original image bands. To
store pyramids, Bioformats uses the TIFF SUBIFD tag to put the pyramid layers
for each band inside the page. 

A two-band OME-TIFF pyramid might look like this:

![Bioformats-style TIFF pyramids]({{ site.baseurl }}/assets/images/new-pyr.png)

libvips has been able to read and write OME-TIFF for a long time, but it
has not been able to read and write these SUBIFD images.

libvips 8.10 adds a new TIFF save option `subifd`. You can now write this:

```
vips copy k2.jpg x.tif[pyramid,subifd]
```

And the pyramid layers will be in a SUBIFD tag off the main image. The `subifd`
option is enabled automatically if you save a multi-page image, so you can
write:

```
vips copy LuCa-7color_Scan1.ome.tiff[n=5] x.tif[pyramid]
```

To take the first five pages (ie. bands) from the OME-TIFF image and write them
as a five-page TIFF, where each page has a pyramid attached to the SUBIFD tag.

There's a matching `subifd` option to TIFF load which you can use to select a
subimage. For example:

```
vips copy x.tif[subifd=2] y.tif
```

Reads the third sub-image from the first page of `x.tif`. 

The libvips thumbnailer knows about subifd pyramids and will exploit them
to speed up image shrinking.

The libvips DeepZoom writer has seen some improvements too: IIIF output is now
more conformant, you can set the IIIF id property, and there are new `min` and
`max` modes for downsize, handy for label images.

# TIFF load and save

As well as OME pyramid support, TIFF load and save has seen some other useful
improvements. There's now a `depth` parameter to set maximum pyramid depth, CIE
XYZ images are saved and loaded as libtiff LOGLUV, and it sets `PAGENUMBER` for
multi-page files.

# 1, 2 and 4 bit images

There's a new `bitdepth` option to the PNG, TIFF and PPM save operations which
lets you set the depth at which images write. 

libvips has supported 1 bit TIFF and PPM save for a long time, but 2 and
4 bit support is new, and the unified interface is an improvement.

# Other file format improvements

libvips 8.9 introduced a new universal image load and save API letting you read
and write to any kind of source and destination. We've now reworked almost all
the load and save operations for this new system.

gifload can now load a wider range of GIF images. PNG save with a bad profile
now just gives a warning rather than failing. A new `subsample-mode` option to
JPG save lets you control chroma subsampling.

# Other

The libvips operation cache now defaults to only 100 entries. The final
parts of vips7 have been revised for vips8. `vipsheader` allows `stdin`
as a filename.  And many even smaller bug fixes and improvements. As usual,
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.
