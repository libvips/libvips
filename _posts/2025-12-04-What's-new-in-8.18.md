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

[A new chapter in the libvips documentation](/API/8.18/uhdr.html) introduces
this feature and explains how to use it. As an example, you can use
`vipsthumbnail` to resize UltraHDR images. This command:

```
$ vipsthumbnail ultra-hdr.jpg --size 500
```

Makes this image:

[ultrahdr thumbnail](/assets/images/tn_ultra-hdr.jpg)

If you view that image on an HDR display and with a web browser that supports
UltraHDR images, the rocket exhaust should look very bright. It should also
look nicely tonemapped on an SDR display.

## Camera RAW support

Thanks to @lxsameer, libvips 8.18 now has support for most camera RAW formats
by wrapping [libraw](https://www.libraw.org). The new 
[`vips_dcrawload()`](/API/8.18/method.Image.dcrawload.html)
operator will automatically import images, for example:

```
$ vipsthumbnail IMG_3260.CR2 --size 500
```

Makes this image

[dcrawload thumbnail](/assets/images/tn_IMG_3260.jpg)


Most time is spent in dcraw, so performance isn't that much better than
the previous solution with imagemagick:

```
$ /usr/bin/time -f %M:%e convert IMG_3260.CR2 -resize 500x x.jpg
442076:1.56
$ /usr/bin/time -f %M:%e vipsthumbnail IMG_3260.CR2 --size 500
359336:1.12
```

But it's convenient to have it all in one thing.

## Support for Oklab colourspace

[Oklab and Oklch](https://en.wikipedia.org/wiki/Oklab_color_space) are a
new colourspaces that are more linear than CIELAB '76, faster to compute,
and support HDR imaging. They have been added to CSS4 and are now supported
by all major web browsers.

libvips supports them like any other colourspace, so you can use Oklab
coordinates in image processing. For example, you could render a watermark in
an Oklab colour like this:

```python
#!/usr/bin/env python3

import sys
import pyvips

im = pyvips.Image.new_from_file(sys.argv[1], access="sequential")
    
# make the watermark 
text = pyvips.Image \   
    .text(sys.argv[3], width=500, dpi=600, align="centre") \
    .rotate(45)
colour = text \
    .cast("float") \
    .new_from_image([float(value) for value in sys.argv[4:]]) \
    .copy(interpretation="oklab") \
    .colourspace("srgb")

# use the text as the alpha, scaled down to make it semi-transparent
text = colour \
        .bandjoin((text * 0.8).cast("uchar")) \
        .copy_memory()

# replicate many times to cover the image
overlay = text \ 
    .replicate(1 + im.width / text.width, 1 + im.height / text.height) \
    .crop(0, 0, im.width, im.height)

# composite on top of the image
im = im.composite(overlay, "over")

im.write_to_file(sys.argv[2])
```

I can run it like this:


$ ./watermark-oklab.py ~/pics/theo.jpg x.jpg "in the beginning was the word" 0.7 0.2 -0.2
```

To generate:

[watermark](/assets/images/tn_watermark.jpg)


A watermarked image, with the watermark colour specified in Oklab coordinates. 

## Improvements to the libvips core

- larger mmap windows on 64-bit machines improve random access mode for many
  file formats
- system: add "cache" argument
- add vips_image_get_tile_width(), vips_image_get_tile_height(): get tile
  cache geometry hints [jbaiter]
- add "path" option to vipsthumbnail, deprecate "output" option [zjturner]
- add vips_interpretation_bands()
- require C++14 as a minimum standard [kleisauke]
- add vips__worker_exit(): enables fast threadpool shutdown

## Better file format support

File format support has been improved (again). Highlights this time are:

- add magickload_source: load from a source with imagemagick
- pdfload: control region to be rendered via `page_box` [lovell]
- add "bitdepth" to jxlsave
- add "exact" to webpsave
- heifsave: add "tune" parameter
