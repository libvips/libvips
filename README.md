# libvips : an image processing library

libvips is an image processing library. It's good for large images and for
colour. There's a GUI as well, see the VIPS website:

	http://www.vips.ecs.soton.ac.uk

There are packages for most unix-like operating systems, and binaries for
Windows and OS X.

# Building libvips from source

In the libvips directory you should just be able to do:

	$ ./configure
	$ make
	$ sudo make install

By default this will install files to /usr/local.

See the Dependencies section below for a list of the things that
libvips needs in order to be able to build.

We have detailed guides on the wiki for [building on
Windows](http://www.vips.ecs.soton.ac.uk/index.php?title=Build_on_windows)
and [building on OS
X](http://www.vips.ecs.soton.ac.uk/index.php?title=Build_on_OS_X).

# Building libvips from GIT

Checkout the latest sources with:

	git clone git://github.com/jcupitt/libvips.git

Then for a debug build:

	$ ./bootstrap.sh
	$ CFLAGS="-g -Wall" CXXFLAGS="-g -Wall" ./configure --prefix=/home/john/vips --enable-gtk-doc
	$ make
	$ make install


# Dependencies 

libvips has to have gettext, glib-2.x and libxml-2.0. The build system needs 
sh, pkg-config and gnu make.

# Optional dependencies

If suitable versions are found, libvips will add support for the following
libraries automatically. See "./configure --help" for a set of flags to
control library detection. Packages are generally found with pkg-config,
so make sure that is working.

libtiff and libjpeg do not usually use pkg-config so libvips looks for
them in the default path and in $prefix. If you have installed your own
versions of these libraries in a different location, libvips will not see
them. Use switches to libvips configure like:

	./configure --prefix=/Users/john/vips \
		--with-tiff-includes=/opt/local/include \
		--with-tiff-libraries=/opt/local/lib \
		--with-jpeg-includes=/opt/local/include \
		--with-jpeg-libraries=/opt/local/lib

or perhaps:

	CFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
		CXXFLAGS="-g -Wall -I/opt/local/include -L/opt/local/lib" \
		./configure --without-python --prefix=/Users/john/vips 

to get libvips to see your builds.

## libjpeg

The IJG JPEG library. 

## libexif

if available, libvips adds support for EXIF metadata in JPEG files

## libtiff

The TIFF library. It needs to be built with support for JPEG and
ZIP compression. 3.4b037 and later are known to be OK. 

## libz

If your TIFF library includes ZIP compression, you'll need this too.

## videodev.h

If libvips finds linux/videodev.h, you get support for Linux video 
grabbing.

## fftw3

If libvips finds this library, it uses it for fourier transforms. It
can also use fftw2, but 3 is faster and more accurate.

## lcms2, lcms

If present, im_icc_import(), _export() and _transform() are available
for transforming images with ICC profiles. If lcms2 is available,
it is used in preference to lcms.

## Large files

libvips uses the standard autoconf tests to work out how to support
large files (>2GB) on your system. Any reasonably recent *nix should
be OK.

## libpng

if present, libvips can load and save png files. 

## libMagick, or optionally GraphicsMagick

if available, libvips adds support for loading all libMagick supported
image file types (about 80 different formats). Use
--with-magickpackage to build against graphicsmagick instead.

## pangoft2

if available, libvips adds support for text rendering. You need the
package pangoft2 in "pkg-config --list-all"

## orc-0.4

if available, vips will accelerate some operations with this run-time
compiler

## matio

if available, vips can load images from Matlab save files

## cfitsio

if available, vips can load FITS images

## OpenEXR

if available, libvips will directly read (but not write, sadly)
OpenEXR images

## OpenSlide

if available, libvips can load OpenSlide-supported virtual slide
files: Aperio, Hamamatsu VMS and VMU, MIRAX, and Trestle

## swig, python, python-dev

if available, we build the python binding too

# Disclaimer

No guarantees of performance accompany this software, nor is any
responsibility assumed on the part of the authors. Please read the licence
agreement.

