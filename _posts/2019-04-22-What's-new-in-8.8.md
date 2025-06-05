---
title: What's new in 8.8
---

libvips 8.8 is [now officially
released](https://github.com/libvips/libvips/releases/tag/v8.8.0), so
here's a quick overview of what's new.  Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Credit to lovell, erdmann, clcaalu, felixbuenemann, GDmac, gvincke, lhecker,
kleisauke, jtorresfabra, martinweihrauch and others for their great work
on this release.

# Support for HEIC images

libvips now has `heifload` and `heifsave` --- load and save for HEIC
images.  This is the new image compression standard being used by Apple
and others. HEIC files are typically half the size of JPEG files at similar 
quality.

It uses the very nice [libheif](https://github.com/strukturag/libheif)
library and, as well as suporting HEIC, should support a range of formats
on the way which are expected to use the heif container.

# Better support for animated images

libvips now supports load and save of animated WebP images, and has better
suport for animated GIFs.

For example:

```
$ vipsthumbnail dancing_banana2.lossless.webp -o x.gif
```

Makes:

![First frame of banana](/assets/images/onebanana.gif)

But:

```
$ vipsthumbnail dancing_banana2.lossless.webp[n=-1] -o x.gif
```

Makes:

![All of banana](/assets/images/manybanana.gif)

It'll work for any many-page format, so you can thumbnail many-page TIFFs,
or even PDFs. For example:

```
$ time vipsthumbnail nipguide.pdf[n=-1] -o x.webp
real  0m0.859s
user  0m0.900s
sys 0m0.085s
```

That's rendering a 40 page PDF as an animated webp image in 0.8s, though I'm 
not sure if it's a useful thing to do.

![All of banana](/assets/images/nipguide.gif)

# Built-in colour profiles

libvips now has two built-in ICC profiles (`srgb` and `cmyk`), you can use
them anywhere, and they are used automatically when necessary. These profiles
are compiled directly into the libvips shared library so there are no extra
files to ship or to get lost.

For example, you can use `colourspace` like this:

```
$ vips colourspace cmyk-no-profile.jpg x.png srgb
```

To convert a CMYK JPEG file to PNG, even when the JPEG has no embedded colour
profile. If the JPEG does have an embedded profile, that will be used in
preference.

You can use the special strings `cmyk` and `srgb` anywhere where you can give
the filename of a colour profile. For example:

```
$ vips icc_export k2.jpg x.tif --output-profile cmyk
```

Will convert a JPEG to a CMYK TIFF.

# Faster thumbnailing of complex image types

Shrink-on-load support has been added to TIFF (for pyramidal images) and
OpenSlide, and `thumbnail` can exploit it. This means you can generate
high-quality thumbnails of huge images very quickly.

For example:

```
$ ls -l 2013_09_20_29.ndpi
-rw-r--r-- 1 john john 4101070956 May  7  2015  2013_09_20_29.ndpi
$ time vipsthumbnail 2013_09_20_29.ndpi
real	0m0.305s
user	0m0.199s
sys	0m0.082s
```

So it can thumbnail a 4GB slide image in 300ms on this laptop.

`thumbnail` also knows about HEIC images and can thumbnail them quickly.

# Other image format improvements

There are a range of other useful improvements to image file handling. PNG
load/save now supports XMP, WebP compression is better, loading GIF 
uses much less memory, magick load and save now supports all metadata,
and finally `dzsave` has better SZI support and a flag that lets you skip
blank tiles.

# Improvements to libvips operators

There are no new operators in this release, but there are quite a few
improvements to the existing ones.

Lovell Fuller has revised `smartcrop` again. It's now much, much faster, and
should produce better results on a wider range of images. As well as `centre`,
you can also now crop low and high.

`composite` has been revised again to improve performance when compositing a
small image on to a large image. Previously, the small image was expanded to the
size of the large image and then joined at every pixel. We've now added a
culling system, so each output area only computes the input images that thouch
it. This can give a huge speed up if you join many small images on to one large
image.

The `text` operator now supports justification.

# Breaking changes

The old Python and C++ interfaces were deprecated in 8.7, and they've now
been removed completely. You no longer need `swig` to build from git. Hooray!

`thumbnail` will now always use EXIF orientation to spin images upright,
and the old `auto_rotate` flags does nothing. There's a new `no_rotate`
option you can set to prevent this behaviour, if you wish.

# Other

Plus many even smaller bug fixes and improvements. As usual, the 
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.
