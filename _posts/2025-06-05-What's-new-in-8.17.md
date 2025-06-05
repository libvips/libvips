---
title: What's new in libvips 8.17
---

Here's a summary of what's new in libvips 8.17. Check the
[ChangeLog](https://github.com/libvips/libvips/blob/master/ChangeLog)
if you need more details.

## New documentation system

We were using gtk-doc for our documentation system. [We've switched to its
newer replacement, gi-docgen](https://www.libvips.org/API/8.17), and it
should be a lot better.

![docs]({{ site.baseurl }}/assets/images/docs.png)

The most interesting improvements are:

- A much better search system -- try typing in the search box at the top left!

- Better and more consistent display of optional arguments, see for example
  [`embed`](https://www.libvips.org/API/8.17/method.Image.embed.html).

- The [class overview page](https://www.libvips.org/API/8.17/class.Image.html)
  includes a useful one-line description of each operator.

- Revised and restructured [Additional
  documentation](https://www.libvips.org/API/8.17/index.html#extra).

- Support for light and dark appearance.

- More consistent markup should make it easier to automatically generate
  documentation for downstream projects.

## Improvements to operators

To help compatibility, the old vips7 matrix multiply
function is now available as a vips8 operator,
[`matrixmultiply`](https://www.libvips.org/API/8.17/method.Image.matrixmultiply.html).

We rewrote the old vips7 `remosaic` function for vips8 years
ago, but stupidly forgot to link it.  We've fixed this, and
[`remosaic`](https://www.libvips.org/API/8.17/method.Image.remosaic.html)
is now proudly available. Similarly,
[`quadratic`](https://www.libvips.org/API/8.17/method.Image.quadratic.html)
has been there for years, but never worked properly. It's been revised and
should now (finally) be useful.

The so-called [magic kernel](https://johncostella.com/magic) is [now
supported](https://www.libvips.org/API/8.17/enum.Kernel.html#mks2021)
for image resize.

ICC import and transform now has an
[`auto`](https://www.libvips.org/API/8.17/enum.Intent.html#auto) option
for rendering intent.

## Better file format support

File format support has been improved (again). Highlights this time are:

- [`gifsave`](https://www.libvips.org/API/8.17/method.Image.gifsave.html)
  has a new `keep_duplicate_frames` option

- [`svgload`](https://www.libvips.org/API/8.17/ctor.Image.svgload.html)
  has a new `stylesheet` option for custom CSS, and a `high_bitdepth` option
  for scRGB output.

- [`heifload`](https://www.libvips.org/API/8.17/ctor.Image.heifload.html)
  has a new `unlimited` flag to remove all load limits, has better alpha
  channel detection, and better detection of truncated files.

- [`jp2kload`](https://www.libvips.org/API/8.17/ctor.Image.jp2kload.html)
  has a new `oneshot` flag which can improve compatibility for older
  jp2k files.

- [`jxlsave`](https://www.libvips.org/API/8.17/method.Image.jxlsave.html)
  has much lower memory use for large images.

- [`openslideload`](https://www.libvips.org/API/8.17/ctor.Image.openslideload.html)
  now shares and reuses connections to the underlying file format library,
  improving speed.

- [`ppmload`](https://www.libvips.org/API/8.17/ctor.Image.ppmload.html)
  has a new buffer variant for convenience.

- TIFF load and save has better error handling 

- A new "convert for save" system fixes a large number of minor bugs and
  inconsistencies in file format support.

## General improvements

There have been some smaller libvips additions and improvements too.

- The
  [`hough_line`](https://www.libvips.org/API/8.17/method.Image.hough_line.html)
  operator has better scaling to Hough space.

- [`shrink`](https://www.libvips.org/API/8.17/method.Image.shrink.html)
  is noticeably faster

- The operation cache is a lot more reliable.

- [`sink_screen`](https://www.libvips.org/API/8.17/method.Image.sink_screen.html)
  has better scheduling and should render thumbnails much more quickly.

- The ICC operators are better at detecting and rejecting corrupt profiles.

Plus some even more minor bugfixes and improvements.
