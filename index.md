---
---

[![CI](https://github.com/libvips/libvips/workflows/CI/badge.svg)](https://github.com/libvips/libvips/actions)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libvips.svg)](https://issues.oss-fuzz.com/issues?q=is:open%20project:libvips)
[![Coverity Status](https://scan.coverity.com/projects/6503/badge.svg)](https://scan.coverity.com/projects/jcupitt-libvips)
[![Gitter](https://badges.gitter.im/libvips/devchat.svg)](https://gitter.im/libvips/devchat?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

libvips is a [demand-driven, horizontally
threaded](https://github.com/libvips/libvips/wiki/Why-is-libvips-quick)
image processing library. Compared to similar
libraries, [libvips runs quickly and uses little
memory](https://github.com/libvips/libvips/wiki/Speed-and-memory-use).
libvips is licensed under the [LGPL-2.1-or-later](
https://spdx.org/licenses/LGPL-2.1-or-later).

It has around [300 operations](API/current/function-list.html) covering
arithmetic, histograms, convolution, morphological operations, frequency
filtering, colour, resampling, statistics and others. It supports a large
range of [numeric types](API/current/enum.BandFormat.html), from 8-bit int
to 128-bit complex. Images can have any number of bands.
It supports a good range of image formats, including JPEG, JPEG 2000, JPEG XL,
TIFF, PNG, WebP, HEIC, AVIF, FITS, Matlab, OpenEXR, PDF, SVG, HDR, PPM / PGM /
PFM, CSV, GIF, Analyze, NIfTI, DeepZoom, and OpenSlide. It can also load
images via ImageMagick or GraphicsMagick, letting it work with formats
like DICOM.

It comes with bindings for [C](API/current/using-from-c.html),
[C++](API/current/using-from-cplusplus.html),
and the [command-line](API/current/using-the-cli.html). Full bindings
are available for [Ruby](https://rubygems.org/gems/ruby-vips),
[Python](https://pypi.python.org/pypi/pyvips),
[PHP](https://github.com/libvips/php-vips),
[.NET](https://www.nuget.org/packages/NetVips),
[Go](https://github.com/cshum/vipsgen),
[Lua](https://github.com/libvips/lua-vips),
[Crystal](https://github.com/naqvis/crystal-vips),
[Elixir](https://github.com/akash-akya/vix),
[Java](https://github.com/lopcode/vips-ffm), and
[Nim](https://github.com/openpeeps/libvips-nim). libvips
is used as an image processing engine by [Mastodon](
https://github.com/mastodon/mastodon), [sharp (on
Node.js)](https://www.npmjs.org/package/sharp),
[imgproxy](https://github.com/imgproxy/imgproxy),
[wsrv.nl](https://github.com/weserv/images),
[bimg](https://github.com/h2non/bimg),
[Ruby on Rails](http://edgeguides.rubyonrails.org/active_storage_overview.html),
[CarrierWave](https://github.com/carrierwaveuploader/carrierwave#using-vips),
[MediaWiki](https://www.mediawiki.org/wiki/Extension:Thumbro), and others.
The official libvips GUI is [nip2](https://github.com/libvips/nip2),
a strange combination of a spreadsheet and a photo editor.

The [download area]({{ site.github.releases_url }}) has the
source code plus pre-compiled binaries for Windows; you can install on macOS
with homebrew, MacPorts or Fink; and it's available in most Linux package
managers. See the [install notes](install.html).

## News

<ul class="blog-index">
  {% for post in site.posts %}
    <li>
      <span class="date">{{ post.date }}</span>
      <h3><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h3>
      {{ post.excerpt }}
    </li>
  {% endfor %}
</ul>
