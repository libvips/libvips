---
title: What's new in 8.9
---

libvips 8.9 will be out RSN, so here's a quick overview of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Credit to lovell, kleisauke, deftomat, omira-sch, meyermarcel, kalozka1,
kayarre, angelmixu, pvdz and others for their great work on this release.

# True streaming

This is the biggest change to libvips in years: it now supports true streaming.

Previously, libvips supported file and memory data sources and sinks. If
you wanted to process images on systems like AWS, you were forced to read
images into memory first, then process back to memory again, then send the
result to the output.

It looked something like this:

![Processing with current libvips]({{ site.baseurl
}}/assets/images/old-libvips-s3.png)

libvips now lets you connect pipelines to any source or destination, so
you can do something more like this:

![Processing with libvips streams]({{ site.baseurl
}}/assets/images/new-libvips-s3.png)

There's no buffering, so there should be a useful drop in latency.

It's really easy to use. For example:

```
aws s3 cp s3://mybucket/input.jpg - | \
    vips thumbnail_stream [descriptor=0] .jpg 128 | \
    aws s3 cp - s3://mybucket/output.jpg
```

You can link it to anything. In ruby-vips, for example, you can make a source
like this:

```ruby
require 'vips'

source = File.open "some/file/name", "rb"
input_stream = Vips::Streamiu.new
input_stream.on_read { |length| source.read length }
image = Vips::Image.new_from_stream input_stream, "", access: "sequential"
```

And you can do anything in the `read` handler. You can define a `seek`
handler as well, if your source supports it. 

Write is just as simple:

```ruby
dest = File.open ARGV[1], "w"
output_stream = Vips::Streamou.new
output_stream.on_write { |chunk| dest.write(chunk) }
output_stream.on_finish { dest.close }

image.write_to_stream output_stream, ".png"
```

There was a [post a few weeks ago]({{ site.baseurl
}}/2019/11/29/True-streaming-for-libvips.html) introducing this in more
detail. pyvips, C and C++ also support this new system.

# OSS-Fuzz integration

Thanks to work by Oscar Mira (@omira-sch), libvips is now part of [OSS
Fuzz](https://github.com/google/oss-fuzz). This is a Google project to
continously test open-source projects for vulnerabilities -- whenever one of
their clusters is idle, it starts analyzing our code.

It's been working away since August and only found two serious bugs, so that's
great, and both have been fixed in 8.8. This means 8.9 should be very solid.

There was a [post a few months ago]({{ site.baseurl
}}2019/08/18/libvips-in-oss-fuzz.html) with a lot more detail, if you're
curious.

# Switch/case

libvips has a pair of new operations which speed up many-way if-then-else.

[`vips_switch()`]({{ site.baseurl
}}/API/8.9/libvips-conversion.html#vips-switch) takes an array of N condition
images and for each pixel finds the index of the first non-zero pixel. If no
pixels are non-zero, it sets the output to N + 1.

[`vips_case()`]({ site.baseurl
}}/API/8.9/API/8.9/libvips-histogram.html#vips-case)
takes an index image plus an array of N + 1 result images and for each
pixel copies the pixel selected by the index to the output. 

Put these two together and you can make a quick many-way if-then-else. For
example, in Python you could write:

```python
import pyvips

texture_names = [
    "k2.jpg",
    "k4.jpg",
    "shark.jpg",
    "k110.jpg"
]
colours = [
    (232, 225, 199),
    (211, 167, 73),
    (210, 125, 60),
    (151, 189, 174)
]

main = pyvips.Image.new_from_file(sys.argv[1], access="sequential")

textures = [pyvips.Image.new_from_file(name)
                .replicate(100, 100)
                .crop(0, 0, main.width, main.height)
            for name in texture_names]

tests = [(main == each_colour).bandand()
         for each_colour in colours]

textured = pyvips.Image.switch(tests).case(textures + [main])

textured.write_to_file(sys.argv[2])
```

So it's finding pixels which equal one of the colours and swapping those pixels
for pixels from the matching texture.

# Image format improvements

There are a range of useful improvements to image file handling. 

Previously, libvips only supported a single delay for all frames of animated
images. Thanks to work by deftomat, it now keeps an array of delays, one per
frame.

Solid WebP images will be automatically written without their alpha band.
`heifsave` has a new `compression` option and (thanks to work by meyermarcel)
supports alpha correctly. `tiffsave` supports `webp` and `zstd` compression
and has more flexibla alpha support. `dzsave` has a new `no-strip` option
and supports IIIF layout. `svgload` has a new `unlimited` option.

# Other

Plus many even smaller bug fixes and improvements. As usual, the 
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.
