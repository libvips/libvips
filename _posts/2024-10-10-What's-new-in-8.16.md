---
title: What's new in libvips 8.16
---

libvips 8.16 is now also done, so here's a summary of what's new. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

## Signed Distance Fields

libvips has a new
[`vips_sdf()`]({{ site.baseurl }}/API/8.16/libvips-create.html#vips-sdf)
operator. This can efficiently generate a range of basic shapes as Signed
Distance Fields -- these are images where each pixel contains a signed value
giving the distance to the closest edge. For example:

```
$ vips sdf x.v 512 512 circle --r=200 --a="256 256"
```

Makes a 512 x 512 pixel float image of a circle with radius 200, centered
on 256 x 256. As you move out and away from the edge, values become
increasingly positive, as you move within the circle, values become negative.

![SDF circle]({{ site.baseurl }}/assets/images/sdf-circle.png)

The great thing about SDFs is that they are quick to make and very easy to
combine to make more complex shapes. For example, you could write:

```python
#!/usr/bin/env python3

import sys
import pyvips

box = pyvips.Image.sdf(1000, 1000, "rounded-box",
                       a=[300, 400],
                       b=[700, 600],
                       corners=[100, 0, 0, 0])

circle = pyvips.Image.sdf(1000, 1000, "circle",
                          a=[500, 300],
                          r=100)

line = pyvips.Image.sdf(1000, 1000, "line",
                        a=[500, 500],
                        b=[600, 900])

# union
sdf = box.minpair(circle).minpair(line)

# make annular
sdf = sdf.abs() - 15

# render as an antialiased image
sdf.clamp().linear(-255, 255, uchar=True).write_to_file(sys.argv[1])
```

To make:

![SDF boat]({{ site.baseurl }}/assets/images/sdf-boat.png)

Hmmm, possibly a person rowing a boat. This uses three
other new operators: [`vips_minpair()`]({{ site.baseurl
}}/API/8.16/libvips-arithmetic.html#vips-minpair) and [`vips_maxpair()`]({{
site.baseurl }}/API/8.16/libvips-arithmetic.html#vips-maxpair),
which given a pair of images find the
pixel-wise max and min, and [`vips_clamp()`]({{ site.baseurl
}}/API/8.16/libvips-arithmetic.html#vips-clamp), which constrains pixels
to a range.

SDFs fit really well with libvips on-demand-evaluation. These things
never really exist, they are just chains of delayed computation, so you can
make them any size, and compute them in parallel.

Up until now we've used SVG rendering to generate masks for large images.
SDFs are a lot faster and need much less memory -- as long as you only need
simple shapes, they should be a great replacement.

## Better file format support

File format support has been improved (again). Highlights this time are:

* JXL load and save now supports exif, xmp, and animation.

* `webpsave` now has `target_size` parameter to set desired size in bytes and a
  `passes` parameter to set number of passes to achieve desired target size,
   plus a `smart_deblock` option for better edge rendering.

* `heifsave` has a new `auto_tiles` option. This can make AVIF encode much
  faster, at the expense of slightly larger filesize.

* `tiffload` supports old-style JPEG compression.

* `tiffsave` now lets you change the deflate compression level.

* All paletteised images now have a `palette` metadata item.

* PFM load and save now uses scRGB colourspace (ie. linear 0-1).

* `rawsave` gets  streaming support with
  [`vips_rawsave_target()`]({{ site.baseurl
  }}/API/8.16/VipsForeignSave.html#vips-rawsave-target) and
  [`vips_rawsave_buffer()`]({{ site.baseurl
  }}/API/8.16/VipsForeignSave.html#vips-rawsave-buffer).


## General improvements

There have been some smaller libvips additions and improvements too.

* libvips used to limit image dimensions to 10 million pixels. This is now
  configurable, see [`vips_max_coord_get()`]({{ site.baseurl
  }}/API/8.16/libvips-vips.html#vips-max-coord-get).

* There's a new (trivial) [`vips_addalpha()`]({{ site.baseurl
   }}/API/8.16/libvips-conversion.html#vips-addalpha) operation.

* `vips_getpoint()` has a new `unpack_complex` option.

* `vipsheader` supports multiple `-f field` arguments.

* libvips now includes basic `g_auto` support, making C programming slightly
  more convenient.

Plus many minor bugfixes and improvements.
