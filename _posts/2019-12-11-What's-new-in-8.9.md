---
title: What's new in 8.9
---

libvips 8.9 is now done, so here's a quick overview of what's new. Check
the [ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

Credit to lovell, kleisauke, deftomat, omira-sch, meyermarcel, kalozka1,
kayarre, angelmixu, pvdz and others for their great work on this release.

# True streaming

This is the biggest change to libvips in years: it now supports true streaming.

Previously, libvips supported file and memory data sources and sinks. If
you wanted to process images on systems like AWS, you were forced to read
to memory first, then process back to memory again, then send the
result to the output.

It looked something like this:

![Processing with current libvips](
/assets/images/old-libvips-s3.png)

libvips now lets you connect pipelines to any source or destination, so
you can do something more like this:

![Processing with libvips streams](
/assets/images/new-libvips-s3.png)

There's no buffering, so there should be a useful drop in latency.

It's really easy to use. For example:

```
aws s3 cp s3://mybucket/input.jpg - | \
  vips thumbnail_source [descriptor=0] .jpg 128 | \
    aws s3 cp - s3://mybucket/output.jpg
```

In ruby-vips you can make a source like this:

```ruby
require 'vips'

source = Vips::Source.new_from_file "some/file/name"
image = Vips::Image.new_from_source source, "", access: "sequential"
```

You can also make sources from file descriptors and memory areas. 

You can make custom sources like this:

```ruby
file = File.open "some/file/name", "rb"
source = Vips::SourceCustom.new
source.on_read { |length| file.read length }
image = Vips::Image.new_from_source source, "", access: "sequential"
```

And you can do anything in the `read` handler. You can define a `seek`
handler as well, if your source supports it. 

Write is just as simple:

```ruby
target = Vips::Target.new_to_file "some/file/name"
image.write_to_target target, ".png"
```

And again you can define custom targets:

```ruby
dest = File.open ARGV[1], "w"
target = Vips::TargetCustom.new
target.on_write { |chunk| dest.write(chunk) }
image.write_to_target target, ".png"
```

There's an optional `finish` handler. 

A [post a few weeks ago](
/2019/11/29/True-streaming-for-libvips.html) introducing this in more
detail. pyvips, C and C++ also support this new feature.

# OSS-Fuzz integration

Thanks to work by Oscar Mira (@omira-sch), libvips is now part of [OSS
Fuzz](https://github.com/google/oss-fuzz). This is a Google project to
continously test open-source projects for vulnerabilities -- whenever one of
their clusters is idle, it starts analyzing our code.

It's been working away since August and only found two serious bugs, so that's
great, and both have been fixed in 8.8. This means 8.9 should be very solid.

There was a [post a few months ago](
2019/08/18/libvips-in-oss-fuzz.html) with a lot more detail, if you're
curious.

# Switch/case

libvips has a pair of new operations which speed up many-way if-then-else.

[`vips_switch()`](
/API/current/type_func.Image.switch.html) takes an array of N condition
images and for each pixel finds the index of the first non-zero pixel. If no
pixels are non-zero, it sets the output to N + 1.

[`vips_case()`](
/API/current/method.Image.case.html)
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

# Breaking changes

There's one serious and breaking change: libvips now blocks metadata
modification in shared images, that is, images with a reference count
greater than one.

You were always supposed to use `copy` to get a unique image before altering
metadata, but this is now enforced. If you attempt it, the change won't happen
and a warning will be issued.

There should be no performance implication, since all `copy` does is
duplicate a few pointers.

This change prevents a range of serious race conditions and possible crashes 
in highly threaded programs.

# Image format improvements

There are a range of useful improvements to image file handling. 

Previously, libvips only supported a single delay for all frames of animated
images. Thanks to work by deftomat, it now keeps an array of delays, one per
frame. Additionally, the meaning of the `loop` parameter is now consistent
between webp and gif.

Solid WebP images will be automatically written without their alpha band.
`heifsave` has a new `compression` option and (thanks to work by meyermarcel)
supports alpha correctly. `tiffsave` supports `webp` and `zstd` compression
and has more flexible alpha support. `dzsave` has a new `no-strip` option
and supports IIIF layout. `svgload` has a new `unlimited` option. PPM load and
save has been rewritten and is now faster and uses less memory.

# Other

Plus many even smaller bug fixes and improvements. As usual, the 
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
has more details, if you're interested.
