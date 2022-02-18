---
---

Most unix-like operating systems have libvips packages, check your package 
manager. For macOS, there are packages in Homebrew, MacPorts and Fink. For
Windows, there are pre-compiled binaries in the [Download area]({{
site.github.releases_url }}).

## Installing on macOS with homebrew

Install [homebrew](https://brew.sh/), then enter:

	brew install vips

That will install vips with most optional add-ons included. 

## Installing the Windows binary

Download `vips-dev-w64-web-x.y.z.zip` from the [Download area]({{ 
site.github.releases_url }}) and unzip somewhere. At the command-prompt, `cd`
to `vips-x.y.z/bin` and run (for example):

	vips.exe invert some/input/file.jpg some/output/file.jpg

If you want to run `vips.exe` from some other directory on your PC, 
you'll need to set your `PATH`.

The zipfile includes all the libraries and headers for developing with C with
any compiler. For C++, you must build with `g++`, or rebuild the C++ API 
with your compiler, or just use the C API. 

The `vips-dev-w64-web-x.y.z.zip` is built with a small set of relatively secure
file format readers and can be used in a potentially hostile environment. The
much larger `vips-dev-w64-all-x.y.z.zip` includes all the file format readers
that libvips supports and care should be taken before public deployment.

The Windows binary is built
by [build-win64](https://github.com/jcupitt/build-win64). This is a
containerised mingw build system: on any host, install Docker, 
clone the project, and type `./build.sh 8.5`. The README has notes.

## Building libvips from source

If the packaged version is too old, you can also build from source. 

libvips uses the [Meson](https://mesonbuild.com) build system, version
0.56 or later. Meson can use ninja, Visual Studio or XCode as a backend,
so you'll also need one of them.

libvips must have `build-essential`, `pkg-config`, `libglib2.0-dev`,
`libexpat1-dev`. See the Dependencies section below for a full list of the
libvips optional dependencies.

Download the sources from the [Download area]({{
site.github.releases_url }}), then something like:

	tar xf libvips-x.y.z.tar.gz
	cd libvips-x.y.z
    meson setup build-dir --prefix=/aaa/bbb/ccc
    cd build-dir
    ninja
    ninja test
    ninja install

Check the output of meson setup carefully and make sure it found everything
you wanted it to find. Add arguments to `meson setup` to change the build
configuration.

 * Add flags like `-Dnsgif=false` to turn options on and off, see
   `meson_options.txt` for a list of all the build options libvips supports.

 * Meson will do a debug build by default. Add `--buildtype=release` for a
   release (optimised) build.

 * You might need to add `--libdir=lib` on Debian if you don't want the arch
   name in the library path.

 * Add `--default-library=static` for a static build.

 * Use eg. `CC=clang CXX=clang++ meson setup ...` to change compiler.

 * You can have many `build-dir`, pick whatever names you like, for example
   one for release and one for debug.

 * On some platforms, you might need to run `ldconfig` after installing.

You'll need the dev packages for the file format support you want. For basic
jpeg and tiff support, you'll need `libtiff5-dev`, `libjpeg-turbo8-dev`,
and `libgsf-1-dev`.  See the **Dependencies** section below for a full list
of the things that libvips can be configured to use.

We have detailed guides on the wiki for [building for
Windows](https://github.com/jcupitt/libvips/wiki/Build-for-Windows) and
[building for macOS](https://github.com/jcupitt/libvips/wiki/Build-for-macOS).

## Dependencies 

libvips has to have `libglib2.0-dev` and `expat`. Other dependencies are
optional, see below.

## Optional dependencies

If suitable versions are found, libvips will add support for the following
libraries automatically. See `./configure --help` for a set of flags to
control library detection. Packages are generally found with `pkg-config`,
so make sure that is working.

Libraries like giflib do not usually use `pkg-config` so libvips looks for
them in the default path and in `$prefix`. If you have installed your own
versions of these libraries in a different location, libvips will not see
them. Use switches to libvips configure like:

	./configure --prefix=/Users/john/vips \
		--with-giflib-includes=/opt/local/include \
		--with-giflib-libraries=/opt/local/lib 

### libjpeg

The IJG JPEG library. Use the `-turbo` version if you can. 

### libexif

If available, libvips adds support for EXIF metadata in JPEG files.

### cgif

If available, libvips will save GIFs with
[cgif](https://github.com/dloebl/cgif).  If this is not present, vips will
try to save gifs via imagemagick instead.

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

### libspng

If present, libvips will load and save png files with
[libspng](https://github.com/randy408/libspng). If not, it will use libpng.

### libimagequant

If present, libvips can write 8-bit palette-ised PNGs and GIFs. If not,
libvips will look for (quantizr)[https://github.com/DarthSim/quantizr].

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
package `pangocairo` and `fontconfig` in `pkg-config --list-all`.

### OpenJPEG

If `libopenjp2` is available, libvips adds support for loading and saving
JPEG2000 images.

### libjxl

If `libjxl` is available, libvips adds support for loading and saving
JXL images.

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

