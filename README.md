# libvips : an image processing library

[![CI](https://github.com/libvips/libvips/workflows/CI/badge.svg)](https://github.com/libvips/libvips/actions)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libvips.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=2&q=proj:libvips)
[![Coverity Status](https://scan.coverity.com/projects/6503/badge.svg)](https://scan.coverity.com/projects/jcupitt-libvips)
[![Gitter](https://badges.gitter.im/libvips/devchat.svg)](https://gitter.im/libvips/devchat?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Introduction

libvips is a [demand-driven, horizontally
threaded](https://github.com/libvips/libvips/wiki/Why-is-libvips-quick)
image processing library. Compared to similar
libraries, [libvips runs quickly and uses little
memory](https://github.com/libvips/libvips/wiki/Speed-and-memory-use).
libvips is licensed under the [LGPL
2.1+](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html).

It has around [300
operations](https://libvips.github.io/libvips/API/current/func-list.html)
covering arithmetic, histograms, convolution, morphological
operations, frequency filtering, colour, resampling,
statistics and others. It supports a large range of [numeric
types](https://libvips.github.io/libvips/API/current/VipsImage.html#VipsBandFormat),
from 8-bit int to 128-bit complex. Images can have any number of bands.
It supports a good range of image formats, including JPEG, JPEG2000, JPEG-XL,
TIFF, PNG, WebP, HEIC, AVIF, FITS, Matlab, OpenEXR, PDF, SVG, HDR, PPM / PGM /
PFM, CSV, GIF, Analyze, NIfTI, DeepZoom, and OpenSlide. It can also load
images via ImageMagick or GraphicsMagick, letting it work with formats
like DICOM.

It comes with bindings for
[C](https://libvips.github.io/libvips/API/current/using-from-c.html),
[C++](https://libvips.github.io/libvips/API/current/using-from-cpp.html),
and the
[command-line](https://libvips.github.io/libvips/API/current/using-cli.html).
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
Rails](https://edgeguides.rubyonrails.org/active_storage_overview.html),
[carrierwave-vips](https://github.com/eltiare/carrierwave-vips),
[mediawiki](https://www.mediawiki.org/wiki/Extension:VipsScaler),
[PhotoFlow](https://github.com/aferrero2707/PhotoFlow) and others.
The official libvips GUI is [nip2](https://github.com/libvips/nip2),
a strange combination of a spreadsheet and a photo editor.

# Install

There are packages for most Unix-like operating systems, including
macOS. Check your package manager.

There are binaries for Windows in
[releases](https://github.com/libvips/libvips/releases).

The [libvips website](https://libvips.github.io/libvips) has [detailed
install notes](https://libvips.github.io/libvips/install.html).

# Building libvips from a source tarball

We keep pre-baked tarballs in
[releases](https://github.com/libvips/libvips/releases).

Untar, then in the libvips directory you should just be able to do:

    ./configure

Check the summary at the end of `configure` carefully.  libvips must have
`build-essential`, `pkg-config`, `libglib2.0-dev`, `libexpat1-dev`.

You'll need the dev packages for the file format support you want. For basic
jpeg and tiff support, you'll need `libtiff5-dev`, `libjpeg-turbo8-dev`,
and `libgsf-1-dev`.  See the **Dependencies** section below for a full list
of the things that libvips can be configured to use.

Once `configure` is looking OK, compile and install with the usual:

    make
    sudo make install

By default this will install files to `/usr/local`.

# Testing

Run the test suite with:

    make check

Run a specific test with:

    pytest test/test-suite/test_foreign.py -k test_tiff

# Building libvips from git

Clone the latest sources with:

    git clone git://github.com/libvips/libvips.git

Building from git needs more packages -- you'll need at least `gtk-doc` 
and `gobject-introspection`, see the dependencies section below. For example:

    brew install gtk-doc 

Then generate the build system with:

    ./autogen.sh --prefix=/home/john/vips

Debug build:

    CFLAGS="-g -Wall" CXXFLAGS="-g -Wall" \
      ./configure --prefix=/home/john/vips --enable-debug
    make
    make install

# Built-in loaders

libvips has a number of built-in loaders and savers. You can disable these if
you wish, for example:

    ./configure --prefix=/Users/john/vips --without-nsgif --without-ppm

# Dependencies 

libvips has to have `libglib2.0-dev` and `libexpat1-dev`. Other dependencies
are optional.

## Optional dependencies

If suitable versions are found, libvips will add support for the following
libraries automatically. See `./configure --help` for a set of flags to
control library detection. Packages are generally found with `pkg-config`,
so make sure that is working.

Libraries like nifti do not use `pkg-config` so libvips will also
look for them in the default path and in `$prefix`. If you have installed
your own versions of these libraries in a different location, libvips will
not see them. Use switches to libvips configure like:

    ./configure --prefix=/Users/john/vips \
      --with-nifti-includes=/opt/local/include \
      --with-nifti-libraries=/opt/local/lib 

or perhaps:

    CFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
      CXXFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
      ./configure --prefix=/Users/john/vips 

### libjpeg

The IJG JPEG library. Use the `-turbo` version if you can. 

### libexif

If available, libvips adds support for EXIF metadata in JPEG files.

### librsvg

The usual SVG loader. If this is not present, vips will try to load SVGs
via imagemagick instead.

### PDFium

If present, libvips will attempt to load PDFs with PDFium. Download the 
prebuilt pdfium binary from: 

    https://github.com/bblanchon/pdfium-binaries

Untar to the libvips install prefix, for example:

    cd ~/vips
    tar xf ~/pdfium-linux.tgz

Create a `pdfium.pc` like this (update the version number):

    VIPSHOME=/home/john/vips
    cat > $VIPSHOME/lib/pkgconfig/pdfium.pc << EOF
         prefix=$VIPSHOME
         exec_prefix=\${prefix}
         libdir=\${exec_prefix}/lib
         includedir=\${prefix}/include
         Name: pdfium
         Description: pdfium
         Version: 4290
         Requires:
         Libs: -L\${libdir} -lpdfium
         Cflags: -I\${includedir}
    EOF

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
can be used to manipulate images with ICC profiles. 

### libspng

If present, libvips will load PNG files using libspng. At the moment, libpng
is still necessary for save.

### libpng

If libspng is not present and libpng is, libvips will load PNG files with
libpng. It will always save PNG files with libpng.

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

### pangocairo

If available, libvips adds support for text rendering. You need the
package pangocairo in `pkg-config --list-all`.

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

If available, vips can load and save NIfTI images.

### OpenEXR

If available, libvips will directly read (but not write, sadly)
OpenEXR images.

### OpenJPEG

If available, libvips will read and write JPEG2000 images.

### libjxl

If available, libvips will read and write JPEG-XL images.

### OpenSlide

If available, libvips can load OpenSlide-supported virtual slide
files: Aperio, Hamamatsu, Leica, MIRAX, Sakura, Trestle, and Ventana.

### libheif

If available, libvips can load and save HEIC and AVIF images. Your libheif (in
turn) needs to be built with the correct decoders and encoders. You can check
with eg.:

```
$ pkg-config libheif --print-variables
builtin_avif_decoder
builtin_avif_encoder
builtin_h265_decoder
builtin_h265_encoder
exec_prefix
includedir
libdir
pcfiledir
prefix
```

# Contributors

### Code Contributors

This project exists thanks to all the people who contribute. 

<a href="https://github.com/libvips/libvips/graphs/contributors"><img src="https://opencollective.com/libvips/contributors.svg?width=890&button=false" /></a>

### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. 

<a href="https://opencollective.com/libvips/organization/0/website"><img src="https://opencollective.com/libvips/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/1/website"><img src="https://opencollective.com/libvips/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/2/website"><img src="https://opencollective.com/libvips/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/3/website"><img src="https://opencollective.com/libvips/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/4/website"><img src="https://opencollective.com/libvips/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/5/website"><img src="https://opencollective.com/libvips/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/6/website"><img src="https://opencollective.com/libvips/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/7/website"><img src="https://opencollective.com/libvips/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/8/website"><img src="https://opencollective.com/libvips/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/libvips/organization/9/website"><img src="https://opencollective.com/libvips/organization/9/avatar.svg"></a>
