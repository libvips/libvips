---
title: What's new in 8.7
---

libvips 8.7 is finally done! 

This post summarizes what's new -- check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

# New operators

libvips has a pair of new edge detectors. [`vips_sobel()`]({{ site.baseurl
}}/API/current/method.Image.sobel.html) is very simple and
is just a useful convenience, but [`vips_canny()`]({{ site.baseurl
}}/API/current/method.Image.canny.html) is rather fancy.

![Canny edge detector]({{ site.baseurl }}/assets/images/canny.png)

[`vips_canny()`]({{ site.baseurl
}}/API/current/method.Image.canny.html) just does the streaming
part of the Canny algorithm. Thresholding and connectivity are up to you.

[`vips_transpose3d()`]({{ site.baseurl
}}/API/current/method.Image.transpose3d.html) is useful for volumetric
images. libvips loads volumes as a single very tall, thin image with all
the image slices one above the other.  This new operation swaps the outer
two dimensions, so output page N is made from all the Nth scanlines in the
input pages.

Finally, [`vips_rotate()`]({{ site.baseurl
}}/API/current/method.Image.rotate.html)  is a convenience
operation that just calls [`vips_similarity()`]({{ site.baseurl
}}/API/current/method.Image.similarity.html) for you. It's supposed
to be easier to find in the API.

# Improvements to existing operators

Thanks for work by fangqiao, [`vips_text()`]({{ site.baseurl
}}/API/current/ctor.Image.text.html) has a new parameter `fontfile`. This
lets you specify a font to render text with, without having to install the
font on your system.

medakk has added `x` and `y` parameters to [`vips_composite()`]({{
site.baseurl }}/API/current/type_func.Image.composite.html), so you
can now position layers relative to each other.

The Hough transform operators have been revised. [`vips_hough_line()`]({{
site.baseurl }}/API/current/method.Image.hough_line.html)
is 4x faster, and [`vips_hough_circle()`]({{ site.baseurl
}}/API/current/method.Image.hough_circle.html) is 2x faster.

There's now a [Mitchell interpolation kernel]({{ site.baseurl
}}/API/current/enum.Kernel.html#mitchell) you can use for image resizing.

# New format support

Work by dlemstra has resulted in [`vips_magicksave()`]({{ site.baseurl
}}/API/current/method.Image.magicksave.html). This new operation can
write an image via libMagick in any format that libMagick supports. It's
still missing some features like ICC profile support,
but it works well for things like animated GIF write.

There's a new, optional PDF loader based on Google's PDFium project. libvips has
had a PDF loader based on poppler-glib for a while, but the poppler GPL
licence is unsuitable for some projects. This new PDFium loader should be more
widely useful.

libvips now has support for [NIfTI](https://nifti.nimh.nih.gov/nifti-1/) load 
and save. This is a popular format for brain imaging.

# Improvements to file format support

felixbuenemann has added support for 8-bit palette PNG
images. These can be quite a bit smaller for some sorts of
image. New parameters for [`vips_pngsave()`]({{ site.baseurl
}}/API/current/method.Image.pngsave.html) let you control the dithering,
number of colours, and quantisation quality.

harukizaemon has added a system to the pyramid
builders in [`vips_dzsave()`]({{ site.baseurl
}}/API/current/method.Image.dzsave.html) and [`vips_tiffsave()`]({{
site.baseurl }}/API/current/method.Image.tiffsave.html) to let you
specify a x2 shrink operation. As well as `mean`, (the previous system) you
can now also specify `mode` and `median`.  These are useful for pyramiding
large label sets.

The [JPEG loader]({{ site.baseurl
}}/API/current/ctor.Image.jpegload.html) has better metadata support. It
will now tell you about the type of source image chroma subsampling, supports
modification of string-valued EXIF tags, supports removal of the embedded
thumbnail, and has a better system for reporting interlaced image sources.

The [PDF loader]({{ site.baseurl }}/API/current/ctor.Image.pdfload.html)
has better support for PDFs with a transparent background, reports the
number of pages in a document, and lets you use PDFium instead of poppler
(see above).

# Infrastructure improvements

## New(-ish) test suite

The libvips test suite was inside the separate
[`pyvips`](https://pypi.org/project/pyvips) project. We've moved it inside
libvips and it's now run automatically on every commit, and by `make check`.

Hopefully this will make it easier to catch errors.

# Breaking changes

Actually using [`vips_hough_line()`]({{ site.baseurl
}}/API/current/method.Image.hough_line.html) in a project revealed
a flaw in the way that it encoded the parameter space. We've had to change
this, but hopefully not too much code will break.

The create functions like [`vips_black()`]({{ site.baseurl
}}/API/current/ctor.Image.black.html) used to set their interpretation
to `b-w` or `multiband` depending on whether they were outputting a single
or a multiband image. This caused quite a bit of confusion, so they now
always set `multiband`, even when outputting single band images.  The rules
for alpha channels have been revised to match.

## vips7 is now off by default

We launched the new vips8 API back in 2015. Now with 8.7, we're making
vips7 off by default.

For C, you'll need to add `#include <vips7compat.h>` to your program to
get the old API.

The vips7 C++ API is not built or installed by default. You'll need to give 
`configure` the `--enable-cpp7` flag.

The vips7 Python interface is not built or installed by default. You'll
need to give `configure` the `--enable-pyvips7` flag.

The vips8 Python interface that came with libvips is also off by
default. You'll need to give `configure` the `--enable-pyvips8` flag. But
you should use [`pyvips`](https://pypi.org/project/pyvips) instead: it's 100%
compatible and can be installed with a simple `pip install pyvips`.

Plus many even smaller bug fixes and improvements. As usual, the 
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.
