Title: Using > Checklist for programmers using libvips

libvips is a slightly unusual library and you may need to take some of its
stranger features into account when you design software that uses it.

## If you can, use [ctor@Image.thumbnail], not [method@Image.resize]

The [ctor@Image.thumbnail] operation combines load and resize into one step.
This lets it take advantage of format library features, such as shrink on
load, and can lead to a large improvement in speed and a large drop in memory
use.

For example, with this JPEG image:

```bash
$ vipsheader nina.jpg
nina.jpg: 6048x4032 uchar, 3 bands, srgb, jpegload
```

I see:

```bash
$ /usr/bin/time -f %M:%e vips resize nina.jpg x.jpg 0.1
123648:0.23
```

124 MB of RAM and 0.23s to shink by a factor of 10. With `thumbnail` it's:

```bash
$ /usr/bin/time -f %M:%e vips thumbnail nina.jpg x.jpg 605
68864:0.08
```

Now it's 68 MB of memory and 0.08s -- half the memory use, and 3x faster. In
fact the improvement is better than that, since the `vips` command takes a
while to start and needs a fair amount of memory:

```bash
$ /usr/bin/time -f %M:%e vips > /dev/null
31232:0.02
```

31 MB and 0.02s, so [ctor@Image.thumbnail] is really 2.5x less memory and
4x faster.

You can see much larger improvements with other formats, and quality will
often be better as well, since [ctor@Image.thumbnail] will automatically
premultiply and can render vector images directly at the correct size.

## Don't use [method@Image.thumbnail_image]

It's just there for emergencies. It can't do any of the rendering tricks,
so it's not faster than [method@Image.resize]. Use [ctor@Image.thumbnail] if
you can.

## Use sequential mode if you can

This is a hint you pass to [ctor@Image.new_from_file] and friends that signals that you
will only scan this image in the direction that the underlying load library
supports. This can give a useful improvement in speed and reduction in memory
use in many cases.

See [the "How it opens files" chapter](how-it-opens-files.html) for background
on this feature.

## Use longer pipelines if you can

libvips is demand-driven, and uses partial images as intermediates. This
means you can construct long pipelines of image processing operations,
they won't use much memory, and they'll (usually) join efficiently.

libvips is horizontally threaded, meaning that threads run along
the pipeline of operations you are evaluating, not up and down images. This
means that libvips can (usually) parallelise longer pipelines more efficiently
than short ones.

If you can, aim for long pipelines of processing operations.

## Cache commonly reused images

If an image is reused repeatedly in one pipeline, it'll be recomputed
each time. You can sometimes get a big speedup by keeping images like
this in memory rather than recalculating their pixels, see (for example),
`copy_memory()` in pyvips.

This can raise memory use, of course.

## Adjust the order of operations in pipelines

If you can, put large resizes right at the start (see [ctor@Image.thumbnail]
above), then area filters (sharpen, for example), and finally any point
operations.

## Only enable the load libraries you need

libvips after version 8.13 has a system for enabling and disabling image load
libraries at runtime, see:

<https://www.libvips.org/2022/05/28/What's-new-in-8.13.html>

You can usually improve security and avoid memory spikes by only enabling
the image formats you really need. If you are handling untrusted data,
I would set the `VIPS_BLOCK_UNTRUSTED` env var and only use the loaders we
have tested for security.

Older versions of libvips need compile-time configuration.

## Sanity-check images before processing

libvips image open is always fast and safe, as long as you have disabled
load via imagemagick. This means you can open an image and sanity-check it
before further processing.

There are two main checks that are very worthwhile:

1. Sanity check image dimensions to protect you from decompression
   bombs like those described at
   <https://www.bamsoftware.com/hacks/deflate.html>

2. Check for interlaced (also called progressive) images.

   These are the ones that appear in low detail first, then progressively
   sharpen as they are downloaded.

   The downside is that you don't get the final pixels until the whole image
   is in memory, which prevents any streaming processing and hugely increases
   memory use. For example:

```bash
$ /usr/bin/time -f %M:%e vipsthumbnail big-progressive.jpg
3732224:4.23
$ vips copy big-progressive.jpg x.jpg
$ /usr/bin/time -f %M:%e vipsthumbnail x.jpg
72448:0.26
```

   So this progressive jpeg takes 4gb of memory and 4.3s to thumbnail, but
   exactly the same image as a regular jpeg takes 72mb and 0.26s.

   I would detect these horrors before processing by looking for the
   `interlaced` metadata item and either ban them, or if your users insist
   on uploading in this terrible format, push them to a separate low-priority
   queue on a special container. Keep them away from your main image path.

## Linux memory allocator

The default memory allocator on most glibc-based Linux systems (e.g.
Debian, Red Hat) is unsuitable for long-running, multi-threaded processes
that involve lots of small memory allocations.

To help avoid fragmentation and improve performance on these systems,
the use of an alternative memory allocator such as [jemalloc](
https://github.com/jemalloc/jemalloc) is recommended.

Those using musl-based Linux (e.g. Alpine) and non-Linux systems are
unaffected.

## Disable the libvips operation cache if you don't need it

The libvips operation cache is not useful for image proxies (i.e. processing
many different images). Consider disabling this with `vips_cache_set_max(0);`.
