# libvips : an image processing library

[![Build Status](https://travis-ci.org/libvips/libvips.svg?branch=master)](https://travis-ci.org/libvips/libvips)
[![Coverity Status](https://scan.coverity.com/projects/6503/badge.svg)](https://scan.coverity.com/projects/jcupitt-libvips)

libvips is a [demand-driven, horizontally
threaded](https://github.com/libvips/libvips/wiki/Why-is-libvips-quick)
image processing library. Compared to similar
libraries, [libvips runs quickly and uses little
memory](https://github.com/libvips/libvips/wiki/Speed-and-memory-use).
libvips is licensed under the [LGPL
2.1+](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html).

It has around [300
operations](http://libvips.github.io/libvips/API/current/func-list.html)
covering arithmetic, histograms, convolution, morphological
operations, frequency filtering, colour, resampling,
statistics and others. It supports a large range of [numeric
types](http://libvips.github.io/libvips/API/current/VipsImage.html#VipsBandFormat),
from 8-bit int to 128-bit complex. Images can have any number of bands.
It supports a good range of image formats, including JPEG, TIFF, PNG,
WebP, HEIC, FITS, Matlab, OpenEXR, PDF, SVG, HDR, PPM / PGM / PFM, CSV,
GIF, Analyze, NIfTI, DeepZoom, and OpenSlide. It can also load images via
ImageMagick or GraphicsMagick, letting it work with formats like DICOM.

It comes with bindings for
[C](http://libvips.github.io/libvips/API/current/using-from-c.html),
[C++](http://libvips.github.io/libvips/API/current/using-from-cpp.html),
and the
[command-line](http://libvips.github.io/libvips/API/current/using-cli.html).
Full bindings are available for [Ruby](https://rubygems.org/gems/ruby-vips),
[Python](https://pypi.python.org/pypi/pyvips),
[PHP](https://github.com/libvips/php-vips),
[C# / .NET](https://www.nuget.org/packages/NetVips),
[Go](https://github.com/davidbyttow/govips), and
[Lua](https://github.com/libvips/lua-vips). libvips
is used as an image processing engine by [sharp
(on node.js)](https://www.npmjs.org/package/sharp),
[bimg](https://github.com/h2non/bimg), [sharp
for Go](https://github.com/DAddYE/vips), [Ruby on
Rails](http://edgeguides.rubyonrails.org/active_storage_overview.html),
[carrierwave-vips](https://github.com/eltiare/carrierwave-vips),
[mediawiki](http://www.mediawiki.org/wiki/Extension:VipsScaler),
[PhotoFlow](https://github.com/aferrero2707/PhotoFlow) and others.
The official libvips GUI is [nip2](https://github.com/libvips/nip2),
a strange combination of a spreadsheet and an photo editor.

# Install

There are packages for most Unix-like operating systems, include macOS. Try
your package manager.

There are binaries for Windows in
[releases](https://github.com/libvips/libvips/releases).

The [libvips website](https://libvips.github.io/libvips) has [detailed
install notes](https://libvips.github.io/libvips/install.html).

# Building libvips from a source tarball

We keep pre-baked tarballs in
[releases](https://github.com/libvips/libvips/releases).

Untar, then in the libvips directory you should just be able to do:

    $ ./configure

Check the summary at the end of `configure` carefully.  libvips must have
`build-essential`, `pkg-config`, `glib2.0-dev`, `libexpat1-dev`.

You'll need the dev packages for the file format support you want. For basic
jpeg and tiff support, you'll need `libtiff5-dev`, `libjpeg-turbo8-dev`,
and `libgsf-1-dev`.  See the **Dependencies** section below for a full list
of the things that libvips can be configured to use.

Once `configure` is looking OK, compile and install with the usual:

    $ make
    $ sudo make install

By default this will install files to `/usr/local`.

# Testing

Do a basic test of your build with:

    $ make check

Run the libvips test suite with:

    $ pytest

Run a specific test with:

    $ pytest test/test-suite/test_foreign.py -k test_tiff

# Building libvips from git

Clone the latest sources with:

    $ git clone git://github.com/libvips/libvips.git

Building from git needs more packages -- you'll need at least `gtk-doc` 
and `gobject-introspection`, see the dependencies section below. For example:

    $ brew install gtk-doc 

Then build the build system with:

    $ ./autogen.sh

Debug build:

    $ CFLAGS="-g -Wall" CXXFLAGS="-g -Wall" \
        ./configure --prefix=/home/john/vips --enable-debug
    $ make
    $ make install

Leak check:

    $ export G_DEBUG=gc-friendly
    $ valgrind --suppressions=libvips.supp \
	       --leak-check=yes \
        vips ... > vips-vg.log 2>&1

Memory error debug:

    $ valgrind --vgdb=yes --vgdb-error=0 vips  ...

valgrind threading check:

    $ valgrind --tool=helgrind vips ... > vips-vg.log 2>&1

Clang build:

    $ CC=clang CXX=clang++ ./configure --prefix=/home/john/vips

Clang static analysis:

    $ scan-build ./configure --disable-introspection --disable-debug
    $ scan-build -o scan -v make 
    $ scan-view scan/2013-11-22-2

Clang dynamic analysis:

    $ FLAGS="-g -O1 -fno-omit-frame-pointer"
    $ CC=clang CXX=clang++ LD=clang \
        CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" LDFLAGS=-fsanitize=address \
        ./configure --prefix=/home/john/vips 

    $ FLAGS="-O1 -g -fsanitize=thread"
    $ FLAGS="$FLAGS -fPIC"
    $ FLAGS="$FLAGS -fno-omit-frame-pointer -fno-optimize-sibling-calls"
    $ CC=clang CXX=clang++ LD=clang \
      CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" \
      LDFLAGS="-fsanitize=thread -fPIC" \
      ./configure --prefix=/home/john/vips \
        --without-magick \
        --disable-introspection
    $ G_DEBUG=gc-friendly vips copy ~/pics/k2.jpg x.jpg >& log

Build with the GCC auto-vectorizer and diagnostics (or just -O3):

    $ FLAGS="-O2 -march=native -ffast-math"
    $ FLAGS="$FLAGS -ftree-vectorize -fdump-tree-vect-details"
    $ CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" \
      ./configure --prefix=/home/john/vips 

Static analysis with:

    $ cppcheck --force --enable=style . &> cppcheck.log

# Dependencies 

libvips has to have `glib2.0-dev`. Other dependencies are optional, see below.

# Optional dependencies

If suitable versions are found, libvips will add support for the following
libraries automatically. See `./configure --help` for a set of flags to
control library detection. Packages are generally found with `pkg-config`,
so make sure that is working.

libtiff, giflib and libjpeg do not usually use `pkg-config` so libvips looks for
them in the default path and in `$prefix`. If you have installed your own
versions of these libraries in a different location, libvips will not see
them. Use switches to libvips configure like:

    ./configure --prefix=/Users/john/vips \
        --with-giflib-includes=/opt/local/include \
        --with-giflib-libraries=/opt/local/lib \
        --with-tiff-includes=/opt/local/include \
        --with-tiff-libraries=/opt/local/lib \
        --with-jpeg-includes=/opt/local/include \
        --with-jpeg-libraries=/opt/local/lib

or perhaps:

    CFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
      CXXFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
      ./configure --prefix=/Users/john/vips 

to get libvips to see your builds.

### libjpeg

The IJG JPEG library. Use the `-turbo` version if you can. 

### libexif

If available, libvips adds support for EXIF metadata in JPEG files.

### giflib

The standard gif loader. If this is not present, vips will try to load gifs
via imagemagick instead.

### librsvg

The usual SVG loader. If this is not present, vips will try to load SVGs
via imagemagick instead.

### PDFium

If present, libvips will attempt to load PDFs via PDFium. This library must be
packaged by https://github.com/jcupitt/docker-builds/tree/master/pdfium

If PDFium is not detected, libvips will look for poppler-glib instead.

### poppler-glib

The Poppler PDF renderer, with a glib API. If this is not present, vips
will try to load PDFs via imagemagick.

### libgsf-1

If available, libvips adds support for creating image pyramids with `dzsave`. 

### libtiff

The TIFF library. It needs to be built with support for JPEG and
ZIP compression. 3.4b037 and later are known to be OK. 

### fftw3

If libvips finds this library, it uses it for fourier transforms. 

### lcms2

If present, `vips_icc_import()`, `vips_icc_export()` and `vips_icc_transform()`
are available for transforming images with ICC profiles. 

### libpng

If present, libvips can load and save png files. 

### libimagequant

If present, libvips can write 8-bit palette-ised PNGs.

### ImageMagick, or optionally GraphicsMagick

If available, libvips adds support for loading all libMagick-supported
image file types. Use `--with-magickpackage=GraphicsMagick` to build against 
graphicsmagick instead.

Imagemagick 6.9+ needs to have been built with `--with-modules`. Most packaged
IMs are, I think.

If you are going to be using libvips with untrusted images, perhaps in a
web server, for example, you should consider the security implications of
enabling a package with such a large attack surface. 

### pangoft2

If available, libvips adds support for text rendering. You need the
package pangoft2 in `pkg-config --list-all`.

### orc-0.4

If available, vips will accelerate some operations with this run-time
compiler.

### matio

If available, vips can load images from Matlab save files.

### cfitsio

If available, vips can load FITS images.

### libwebp

If available, vips can load and save WebP images.

### libniftiio

If available, vips can load and save NIFTI images.

### OpenEXR

If available, libvips will directly read (but not write, sadly)
OpenEXR images.

### OpenSlide

If available, libvips can load OpenSlide-supported virtual slide
files: Aperio, Hamamatsu, Leica, MIRAX, Sakura, Trestle, and Ventana.

### libheif

If available, libvips can load and save HEIC images. 

# Disclaimer

No guarantees of performance accompany this software, nor is any
responsibility assumed on the part of the authors. Please read the licence
agreement.

