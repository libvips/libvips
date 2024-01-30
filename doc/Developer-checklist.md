  <refmeta>
    <refentrytitle>Developer checklist</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>libvips</refmiscinfo>
  </refmeta>

  <refnamediv>
    <refname>Dev checklist</refname>
    <refpurpose>Checklist for libvips users</refpurpose>
  </refnamediv>

libvips is a slightly unusual library and you may need to take some of its
stranger features into account when you design software that uses it.

## If you can, use `thumbnail`, not `resize`

The `thumbnail` operation combines load and resize into one step. This lets it
take advantage of format library features, such as shrink on load, and can
lead to a large improvement in speed and drop in memory use.

For example, with this JPEG image:

```
$ vipsheader nina.jpg
nina.jpg: 6048x4032 uchar, 3 bands, srgb, jpegload
```

I see:

```
$ /usr/bin/time -f %M:%e vips resize nina.jpg x.jpg 0.1
123648:0.23
```

124 MB of RAM and 0.23s to shink by a factor of 10. With `thumbnail` it's:

```
$ /usr/bin/time -f %M:%e vips thumbnail nina.jpg x.jpg 605
68864:0.08
```

Now it's 68 MB of memory and 0.08s -- half the memory use, and 3x faster. In
fact the improvement is better than that, since the ``vips` command takes a
while to start and needs a fair amount of memory:

```
$ /usr/bin/time -f %M:%e vips > /dev/null
31232:0.02
```

31 MB and 0.02s, so `thumbnail` is really 2.5x less memory and 4x faster.

You can see much larger improvements with other formats, and quality will
often be better as well, since `thumbnail` will automatically premultiply and
can render vector images directly at the correct size.

## Don't use `thumbnail_image`

It's just there for emergencies. It can't do any of the rendering tricks,
so it's no faster than `resize`. Use `thumbnail` if you can.

## Use sequential mode if you can

This is a hint you pass to `new_from_file` and friends that signals that you
will only scan this image in the direction that the underlying load library
supports. This can give a useful improvement in speed and reduction in memory
use in many cases.

See [the "How it opens files"](How-it-opens-files.html) chapter for background
on this feature.

## Use longer pipelines if you can

libvips is demand-driven, and uses *partial images* as intermediates. This
means you can construct long pipelines of image processing operations,
they won't use much memory, and they'll (usually) join efficiently.

libvips is *horizontally threaded*, meaning that threads run along
the pipeline of operations you are evaluating, not up and down images. This
means that libvips can (usually) parallelise longer pipelines more efficiently
than short ones.

If you can, aim for long pipelines of processing operations.

## Adjust the order of operations in pipelines

If you can, put large resizes right at the start (see `thumbnail` above),
then area filters (sharpen, for example), and finally any point operations.

## Disable or adjust imagemagick

If libvips sees a format it does not support (eg. PSB, BMP, ICO, NIF etc.) it
falls back to loading via imagemagick. This usually gets you an image,
but it can cause *huge* memory spikes. For example:

```
$ /usr/bin/time -f %M:%e vipsheader bigphoto.psb
bigphoto.psb: 23847x12799 uchar, 3 bands, srgb, magickload
3325952:4.51
$
```

So 3.3gb and 4.5s just to get the header of a PSB file. It's 10s to make
a thumbnail.

Suggestions:

- make a list of the file formats you need to support, and be quite ruthless

- if you can live without imagemagick, then remove it

- or perhaps adjust your `policy.xml` to ban huge imagemagick images

- you can also detect these images ahead of processing in python and divert
  images which will need imagemagick to another container so as not to kill
  your main image path

## Block untrusted loaders

We fuzz libvips for security, but only for a subset of the supported
loaders. Some loaders are not designed for untrusted data and can be
easily exploited. They should not be exposed to uploads.

Many libvips binaries (eg. Debian, RHEL, etc.) ship with all of these bad
loaders enabled. Since 8.13 we've had a feature to disable them at runtime:

https://www.libvips.org/2022/05/28/What's-new-in-8.13.html

If you are handling untrusted data, I would set the `VIPS_BLOCK_UNTRUSTED`
env var and only use the tested loaders.

## Interlaced (or progressive) images

PNG and JPG both support interlaced (also called progressive) images --
these are the ones that appear at a low res first, then slowly fill in
detail as they are downloaded.

The downside is that you don't get the final pixels until the whole image
is in memory, which prevents any streaming processing and hugely increases
memory use. For example:

```
$ /usr/bin/time -f %M:%e vipsthumbnail big-progressive.jpg
3732224:4.23
$ vips copy big-progressive.jpg x.jpg
$ /usr/bin/time -f %M:%e vipsthumbnail x.jpg
72448:0.26
$
```

So this progressive jpeg takes 4gb of memory and 4.3s to thumbnail, but
exactly the same image as a regular jpeg takes 72mb and 0.26s.

I would detect these horrors before processing and either ban them, or
if your users insist on uploading in this terrible format, push them to
a separate low-priority queue on a special container. Keep them away from
your main image path.

