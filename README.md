[![Build Status](https://travis-ci.org/jcupitt/libvips.svg?branch=master)](https://travis-ci.org/jcupitt/libvips)
[![Coverity Status](https://scan.coverity.com/projects/6503/badge.svg)](https://scan.coverity.com/projects/jcupitt-libvips)

libvips is a 2D image processing library. Compared to similar libraries, 
[libvips runs quickly and uses little 
memory](http://www.vips.ecs.soton.ac.uk/index.php?title=Speed_and_Memory_Use).
libvips is licensed under the LGPL 2.1+.

It has around 300 operations covering arithmetic, histograms,
convolutions, morphological operations, frequency filtering, colour,
resampling, statistics and others. It supports a large range of numeric
formats, from 8-bit int to 128-bit complex. It supports a good range of
image formats, including JPEG, TIFF, PNG, WebP, FITS, Matlab, OpenEXR,
PDF, SVG, HDR, PPM, CSV, GIF, Analyze, DeepZoom, and OpenSlide.  It can
also load images via ImageMagick or GraphicsMagick.

It has APIs for [C](API/using-from-c.html) and [C++](API/using-from-cpp.html)
and comes with a [Python binding](API/using-from-python.html) and a 
[command-line interface](API/using-cli.html). Bindings are available for 
[Ruby](https://rubygems.org/gems/ruby-vips), 
[PHP](https://github.com/jcupitt/php-vips),
[Go](https://github.com/davidbyttow/govips), JavaScript and others. There are 
several GUIs as well.

<h1>News</h1>

<ul class="blog-index">
  {% for post in site.posts %}
    <li>
      <span class="date">{{ post.date }}</span>
      <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
      {{ post.excerpt }}
    </li>
  {% endfor %}
</ul>
