---
---

[![Build Status](https://travis-ci.org/jcupitt/libvips.svg?branch=master)](https://travis-ci.org/jcupitt/libvips)
[![Coverity Status](https://scan.coverity.com/projects/6503/badge.svg)](https://scan.coverity.com/projects/jcupitt-libvips)

libvips is a [demand-driven, horizontally threaded](https://github.com/jcupitt/libvips/wiki/Why-is-libvips-quick) image processing library. Compared to
similar libraries, [libvips runs quickly and uses little
memory](https://github.com/jcupitt/libvips/wiki/Speed-and-memory-use).
The [download area]({{ site.github.releases_url }}) has the
source code plus pre-compiled binaries for Windows. You can install on macOS
with homebrew, MacPorts or Fink, and it's available in most Linux package
managers, see the [install notes](install.html).  libvips is licensed under
the [LGPL 2.1+](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html).

It has around [300 operations](API/current/func-list.html) covering
arithmetic, histograms, convolution, morphological operations, frequency
filtering, colour, resampling, statistics and others. It supports a large
range of [numeric formats](API/current/VipsImage.html#VipsBandFormat),
from 8-bit int to 128-bit complex. Images can have any number of bands.
It supports a good range of image formats, including JPEG, TIFF, OME-TIFF,
PNG, WebP, FITS, Matlab, OpenEXR, PDF, SVG, HDR, PPM, CSV, GIF, Analyze,
DeepZoom, and OpenSlide.  It can also load images via ImageMagick or
GraphicsMagick, letting it load formats like DICOM. 

It comes with bindings for [C](API/current/using-from-c.html),
[C++](API/current/using-from-cpp.html),
[Python](API/current/using-from-python.html) and [the
command-line](API/current/using-cli.html). Full bindings
are available for [Ruby](https://rubygems.org/gems/ruby-vips),
[PHP](https://github.com/jcupitt/php-vips), 
[Go](https://github.com/davidbyttow/govips), and
[Lua](https://github.com/jcupitt/lua-vips). libvips
is used as an image processing engine by [sharp (on
node.js)](https://www.npmjs.org/package/sharp),
[bimg](https://github.com/h2non/bimg),
[sharp for Go](https://github.com/DAddYE/vips),
[carrierwave-vips](https://github.com/eltiare/carrierwave-vips),
[mediawiki](http://www.mediawiki.org/wiki/Extension:VipsScaler),
[PhotoFlow](https://github.com/aferrero2707/PhotoFlow) and others.
The official libvips GUI is [nip2](https://github.com/jcupitt/nip2),
a strange combination of a spreadsheet and an photo editor.

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
