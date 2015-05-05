# Process this file with autoconf to produce a configure script.

# also update the version number in the m4 macros below

AC_INIT([vips], [8.0.2], [vipsip@jiscmail.ac.uk])
# required for gobject-introspection
AC_PREREQ(2.62)

# gobject-introspection recommends -Wno-portability
# foreign stops complaints about a missing README (we use README.md instead)
# and missing INSTALL (the standard Gnu INSTALL is not very useful)
# subdir-objects lets us have dumy.cc in a subdir
AM_INIT_AUTOMAKE([-Wno-portability foreign subdir-objects])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

# user-visible library versioning
m4_define([vips_major_version], [8])
m4_define([vips_minor_version], [0])
m4_define([vips_micro_version], [2])
m4_define([vips_version],
          [vips_major_version.vips_minor_version.vips_micro_version])

VIPS_MAJOR_VERSION=vips_major_version()
VIPS_MINOR_VERSION=vips_minor_version()
VIPS_MICRO_VERSION=vips_micro_version()
VIPS_VERSION=vips_version()
VIPS_VERSION_STRING=$VIPS_VERSION-`date`

# libtool library versioning ... not user-visible (except as part of the
# library file name) and does not correspond to major/minor/micro above

# rules:
# sources changed: increment revision
# binary interface changed: increment current, reset revision to 0
#   binary interface changes backwards compatible?: increment age
#   binary interface changes not backwards compatible?: reset age to 0

LIBRARY_CURRENT=42
LIBRARY_REVISION=0
LIBRARY_AGE=0

# patched into include/vips/version.h
AC_SUBST(VIPS_VERSION)
AC_SUBST(VIPS_VERSION_STRING)
AC_SUBST(VIPS_MAJOR_VERSION)
AC_SUBST(VIPS_MINOR_VERSION)
AC_SUBST(VIPS_MICRO_VERSION)

# put into library name by libsrc/Makefile.am and libsrcCC/Makefile.am
AC_SUBST(LIBRARY_CURRENT)
AC_SUBST(LIBRARY_REVISION)
AC_SUBST(LIBRARY_AGE)

# init introspection support
GOBJECT_INTROSPECTION_CHECK([1.30.0])

# gir needs a list of source files to scan for introspection
#
# build with a glob and a list of files to exclude from scanning
# see also IGNORE_HFILES in doc/Makefile.am
introspection_sources=$(cd libvips ; find . -name "*.c")
filter_list="deprecated "

# contains(string, substring)
#
# Returns 0 if the specified string contains the specified substring,
# otherwise returns 1.
contains() {
  string="$1"
  substring="$2"
  if test "${string#*$substring}" != "$string"; then
    return 0    # $substring is in $string
  else
    return 1 	# $substring is not in $string
  fi
}

introspection_sources2=
for name in $introspection_sources; do
  found=0
  for filter in $filter_list; do
    if contains $name ${filter}; then
      found=1
    fi
  done    

  if [[ $found -eq 0 ]]; then
    introspection_sources2="$introspection_sources2 $name"
  fi      
done    
vips_introspection_sources="$introspection_sources2"

# add headers that form the public vips8 API .. don't do a find and exclude,
# we end up excluding almost everything argh
headers="\
	basic.h \
	vips.h \
	object.h \
	image.h \
	error.h \
	foreign.h \
	interpolate.h \
	header.h \
	operation.h \
	enumtypes.h \
	conversion.h \
	arithmetic.h \
	colour.h \
	convolution.h \
	draw.h \
	morphology.h \
	type.h \
	region.h"

for name in $headers; do
  vips_introspection_sources="$vips_introspection_sources include/vips/$name"
done

AC_SUBST(vips_introspection_sources)

AC_CANONICAL_HOST

AC_DEFINE_UNQUOTED(G_LOG_DOMAIN, "VIPS", [Domain for glib logging messages.])

# disable debugging by default for production releases
m4_define([debug_default],
  m4_if(m4_eval(vips_minor_version() % 2), [1], [yes], [no]))

AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--enable-debug=@<:@no/minimum/yes@:>@],
    [turn on debugging @<:@default=debug_default()@:>@]),,
  enable_debug=debug_default())

if test "x$enable_debug" = "xyes"; then
  VIPS_DEBUG_FLAGS="-DDEBUG_FATAL -DDEBUG_LEAK"
else
  VIPS_DEBUG_FLAGS="-DG_DISABLE_CAST_CHECKS"

  if test "x$enable_debug" = "xno"; then
    VIPS_DEBUG_FLAGS="-DG_DISABLE_ASSERT -DG_DISABLE_CHECKS"
  fi
fi

# option to disable deprecated code, shaves a bit off the library size
AC_ARG_ENABLE(deprecated,
  AS_HELP_STRING([--enable-deprecated], [build deprecated components (default: yes)]))

VIPS_ENABLE_DEPRECATED=0
if test x"$enable_deprecated" != x"no"; then
  VIPS_ENABLE_DEPRECATED=1
  enable_deprecated=yes
  AM_CONDITIONAL(ENABLE_DEPRECATED, true)
else
  AM_CONDITIONAL(ENABLE_DEPRECATED, false)
fi

# this gets pasted into version.h as a #define
AC_SUBST(VIPS_ENABLE_DEPRECATED)

# we are a C library with some optional C++ components inside it

# on most platforms, but not all, we just include -lstdc++ in the link line 
# for programs

# we ought to write a proper configure test for this :( 

AC_MSG_CHECKING([for needs -lstdc++])
case "$host_os" in
  freebsd*)
    vips_needs_stdcpp=no
    ;;
  *)
    vips_needs_stdcpp=yes
    ;;
esac
AC_MSG_RESULT([$vips_needs_stdcpp])

AC_MSG_CHECKING([for native Win32])
case "$host" in
  *-*-mingw*)
    vips_os_win32=yes
    ;;
  *)
    vips_os_win32=no
    ;;
esac
AC_MSG_RESULT([$vips_os_win32])

if test x"$vips_os_win32" = "xyes"; then
  AC_DEFINE(OS_WIN32,1,[native win32])

  # makes gcc use win native alignment
  VIPS_CFLAGS="-mms-bitfields $VIPS_CFLAGS"
fi

# CImg needs flags changed on win32
if test x"$vips_os_win32" = "xyes"; then
  AM_CONDITIONAL(OS_WIN32, true)
else
  AM_CONDITIONAL(OS_WIN32, false)
fi

# Cygwin/mingw need binary open to avoid CR/LF madness
# ... should be a better way to test for this
AC_MSG_CHECKING([for binary open needed])
case "$host_os" in
  cygwin* | mingw*)
    vips_binary_open=yes
    ;;
  *)
    vips_binary_open=no
    ;;
esac
AC_MSG_RESULT([$vips_binary_open])
if test x"$vips_binary_open" = "xyes"; then
  AC_DEFINE(BINARY_OPEN,1,[define to open non-text files in binary mode])
fi

AC_MSG_CHECKING([for Mac OS X])
case "$host" in
  *-*-darwin*)
    vips_os_darwin=yes
    ;;
  *)
    vips_os_darwin=no
    ;;
esac
AC_MSG_RESULT([$vips_os_darwin])

if test x"$vips_os_darwin" = x"yes"; then
  AC_DEFINE(VIPS_OS_DARWIN,1,[native Mac OS X])
fi

# set the default directory for ICC profiles
if test x"$vips_os_darwin" = x"yes"; then
  profile_dir="/Library/ColorSync/Profiles"
elif test x"$vips_os_win32" = x"yes"; then
  profile_dir="C:\\Windows\\System32\\spool\\drivers\\color"
else
  profile_dir="/usr/share/color/icc"
fi
AC_DEFINE_UNQUOTED(VIPS_ICC_DIR,"$profile_dir",[default directory for ICC profiles])

# we want largefile support, if possible
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
AC_C_CONST
AC_C_RESTRICT
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_LN_S
AM_WITH_DMALLOC

# we need a fully expanded version of $libdir
# without this we get something like
#    define VIPS_LIBDIR ${exec_prefix}/lib
# argh
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

# set $expanded_value to the fully-expanded value of the argument
expand () {
	eval expanded_value=$1

	if test x"$expanded_value" != x"$1"; then
		expand "$expanded_value"
	fi
}

expand $libdir
VIPS_LIBDIR=$expanded_value

# this gets pasted into version.h as a #define
VIPS_EXEEXT=$EXEEXT
AC_SUBST(VIPS_EXEEXT)

# vips.c/im_guess_prefix.c need to know the exe suffix and (as a fallback)
# the configure-time install prefix
AC_DEFINE_UNQUOTED(VIPS_PREFIX,"$prefix",[configure-time install prefix])
AC_DEFINE_UNQUOTED(VIPS_LIBDIR,"$VIPS_LIBDIR",[configure-time library directory])

# i18n
# we need to name our .mo with major.minor so we can have multiple versions
# installed in parallel on Debian
expand vips$VIPS_MAJOR_VERSION.$VIPS_MINOR_VERSION
GETTEXT_PACKAGE=$expanded_value

AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE",
        [The prefix for our gettext translation domains.])
# the 'malkovich' one is there for testing only, remove for release
#ALL_LINGUAS="en_GB de malkovich"
ALL_LINGUAS="en_GB de"
AM_GLIB_GNU_GETTEXT

# Checks for libraries.

# build list of pkg-config packages we used here
PACKAGES_USED=""

# build list of extra libs we need here
# the main one is jpeg: it does not have a .pc file, so when we make vips.pc
# we need to put -ljpeg into libs ourselves
EXTRA_LIBS_USED=""

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h math.h fcntl.h limits.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/time.h sys/mman.h sys/types.h sys/stat.h unistd.h io.h direct.h windows.h])

# uncomment to change which libs we build
# AC_DISABLE_SHARED
# AC_DISABLE_STATIC
AC_LIBTOOL_WIN32_DLL
AC_CHECK_TOOL(DLLWRAP, dllwrap)
AC_CHECK_TOOL(DLLTOOL, dlltool)
AC_CHECK_TOOL(OBJDUMP, objdump)
AC_CHECK_TOOL(RANLIB, ranlib)
AC_CHECK_TOOL(STRIP, strip)
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(AS, as)
AC_CHECK_TOOL(LD, ld)
AC_PROVIDE([AC_LIBTOOL_WIN32_DLL])
AC_PROG_LIBTOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getcwd gettimeofday getwd memset munmap putenv realpath strcasecmp strchr strcspn strdup strerror strrchr strspn vsnprintf realpath mkstemp mktemp random rand sysconf atexit])
AC_CHECK_LIB(m,cbrt,[AC_DEFINE(HAVE_CBRT,1,[have cbrt() in libm.])])
AC_CHECK_LIB(m,hypot,[AC_DEFINE(HAVE_HYPOT,1,[have hypot() in libm.])])

# have to have these
# need glib 2.6 for GOption
PKG_CHECK_MODULES(REQUIRED, glib-2.0 >= 2.6 gmodule-2.0 libxml-2.0 gobject-2.0)
PACKAGES_USED="$PACKAGES_USED glib-2.0 libxml-2.0 gmodule-2.0 gobject-2.0"

# after 2.28 we have a monotonic timer
PKG_CHECK_MODULES(MONOTONIC, glib-2.0 >= 2.28,[
  AC_DEFINE(HAVE_MONOTONIC_TIME,1,[define if your glib has g_get_monotonic_time().])
  ],[:
  ]
)

# after 2.32 there are a new set of thread functions, annoyingly
PKG_CHECK_MODULES(THREADS, glib-2.0 >= 2.32,[
  AC_DEFINE(HAVE_MUTEX_INIT,1,[define if your glib has g_mutex_init().])
  AC_DEFINE(HAVE_COND_INIT,1,[define if your glib has g_cond_init().])
  AC_DEFINE(HAVE_THREAD_NEW,1,[define if your glib has g_thread_new().])
  AC_DEFINE(HAVE_PRIVATE_INIT,1,[define if your glib has G_PRIVATE_INIT().])
  AC_DEFINE(HAVE_VALUE_GET_SCHAR,1,[define if your glib has g_value_get_schar().])
  ],[
    # the old threading system ... we need to link against gthread
    PKG_CHECK_MODULES(GTHREAD, gthread-2.0)
    PACKAGES_USED="$PACKAGES_USED gthread-2.0"
  ]
)

# with 2.36 and after the type system inits itself
PKG_CHECK_MODULES(TYPE_INIT, glib-2.0 < 2.36,[
  AC_DEFINE(NEED_TYPE_INIT,1,[define if your glib needs g_type_init().])
  ],[:
  ]
)

# check for gtk-doc
GTK_DOC_CHECK([1.14],[--flavour no-tmpl])

# optional supporting libraries

AC_ARG_WITH([gsf], 
  AS_HELP_STRING([--without-gsf], [build without libgsf-1 (default: test)]))

# libgsf-1 1.14.21 crashes, .27 is known-good, not sure about 22-26
if test x"$with_gsf" != "xno"; then
  PKG_CHECK_MODULES(GSF, libgsf-1 >= 1.14.27,
    [AC_DEFINE(HAVE_GSF,1,[define if you have libgsf-1 installed.])
     with_gsf=yes
     PACKAGES_USED="$PACKAGES_USED libgsf-1"],
    [AC_MSG_WARN([libgsf-1 not found; disabling dzsave support]) 
     with_gsf=no])
fi

AC_ARG_WITH([fftw], 
  AS_HELP_STRING([--without-fftw], [build without fftw (default: test)]))

if test x"$with_fftw" != "xno"; then
  PKG_CHECK_MODULES(FFTW, fftw3,
    [AC_DEFINE(HAVE_FFTW,1,[define if you have fftw3 installed.])
     with_fftw=yes
     PACKAGES_USED="$PACKAGES_USED fftw3"],
    [AC_MSG_WARN([fftw not found; disabling fftw support]) 
     with_fftw=no])
fi

# ImageMagick ... detect attribute iteration too
# Optionally look for GraphicsMagick instead ... use
# --with-magickpackage=GraphicsMagick
AC_ARG_WITH([magick], 
  AS_HELP_STRING([--without-magick], [build without libMagic (default: test)]))
AC_ARG_WITH([magickpackage], 
  AS_HELP_STRING([--with-magickpackage], 
    [magickpackage to use (default: MagickWand, ImageMagick; try GraphicsMagick to build against gm instead)]))

# recent versions of ImageMagick have split parts of the library off to
# MagickWand, so by default we test for that first
if test x"$with_magickpackage" = "x"; then
  PKG_CHECK_MODULES(MAGICK_WAND, MagickWand,
    [with_magickpackage=MagickWand],
    [PKG_CHECK_MODULES(IMAGE_MAGICK, ImageMagick,
     [with_magickpackage=ImageMagick],
     [AC_MSG_WARN([neither MagickWand nor ImageMagick found; disabling Magick support])
      with_magick=no
     ])])
fi

if test x"$with_magick" != "xno"; then
  PKG_CHECK_MODULES(MAGICK, $with_magickpackage, 
    [AC_DEFINE(HAVE_MAGICK,1,[define if you have libMagick installed.])
     with_magick=yes
     PACKAGES_USED="$PACKAGES_USED $with_magickpackage"],
    [AC_MSG_WARN([$with_magickpackage not found; disabling Magick support])
     with_magick=no
    ])
fi

if test x"$with_magick" != "xno"; then
  # we SetImageOption to disable some DICOM read processing, but that's only
  # in more recent imagemagicks and not in graphicsmagick
  save_LIBS=$LIBS
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(SetImageOption,
    AC_DEFINE(HAVE_SETIMAGEOPTION,1,
	      [define if your magick has SetImageOption.]))
  LIBS=$save_LIBS
fi

if test x"$with_magick" != "xno"; then
  # newer ImageMagicks use MagickCoreGenesis instead of InitializeMagick argh
  save_LIBS=$LIBS
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(MagickCoreGenesis,
    AC_DEFINE(HAVE_MAGICKCOREGENESIS,1,
	      [define if your magick has MagickCoreGenesis.]))
  LIBS=$save_LIBS
fi

if test x"$with_magick" != "xno"; then
  # newer ImageMagicks use ResetImagePropertyIterator instead of
  # ResetImageAttributeIterator argh
  save_LIBS=$LIBS
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(ResetImagePropertyIterator,
    AC_DEFINE(HAVE_RESETIMAGEPROPERTYITERATOR,1,
	      [define if your magick has ResetImagePropertyIterator.]))
  LIBS=$save_LIBS
fi

if test x"$with_magick" != "xno"; then
  # so ... do we have ResetImageAttributeIterator()? GM does not
  save_LIBS=$LIBS
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(ResetImageAttributeIterator,
    AC_DEFINE(HAVE_RESETIMAGEATTRIBUTEITERATOR,1,
	      [define if your magick has ResetImageAttributeIterator.]))
  LIBS=$save_LIBS
fi

if test x"$with_magick" != "xno"; then
  # more recent magicks have GetVirtualPixels rather than GetImagePixels
  save_LIBS=$LIBS
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(GetVirtualPixels,
    AC_DEFINE(HAVE_GETVIRTUALPIXELS,1,
	      [define if your magick has GetVirtualPixels.]))
  LIBS=$save_LIBS
fi

# orc
AC_ARG_WITH([orc], 
  AS_HELP_STRING([--without-orc], [build without orc (default: test)]))

if test x"$with_orc" != "xno"; then
  # we use loadpw etc.
  PKG_CHECK_MODULES(ORC, orc-0.4 >= 0.4.11,
    [AC_DEFINE(HAVE_ORC,1,[define if you have orc-0.4.11 or later installed.])
     with_orc=yes
     PACKAGES_USED="$PACKAGES_USED orc-0.4"],
    [AC_MSG_WARN([orc-0.4.11 or later not found; disabling orc support])
     with_orc=no
    ])
fi

# lcms ... look for lcms2 first, it has better threading support
AC_ARG_WITH([lcms], 
  AS_HELP_STRING([--without-lcms], [build without lcms (default: test)]))

if test x"$with_lcms" != "xno"; then
  PKG_CHECK_MODULES(LCMS, lcms2,
    [AC_DEFINE(HAVE_LCMS2,1,[define if you have lcms2 installed.])
     with_lcms="yes (lcms2)"
     PACKAGES_USED="$PACKAGES_USED lcms2"],
    [PKG_CHECK_MODULES(LCMS, lcms,
     [AC_DEFINE(HAVE_LCMS,1,[define if you have lcms installed.])
      with_lcms="yes (lcms1)"
      PACKAGES_USED="$PACKAGES_USED lcms"],
     [AC_MSG_WARN([lcms2/lcms not found; disabling lcms support])
      with_lcms=no])   
    ])
fi

# OpenEXR
AC_ARG_WITH([OpenEXR], 
  AS_HELP_STRING([--without-OpenEXR], [build without OpenEXR (default: test)]))

# require 1.2.2 since 1.2.1 has a broken ImfCloseTiledInputFile()
if test x"$with_OpenEXR" != "xno"; then
  PKG_CHECK_MODULES(OPENEXR, OpenEXR >= 1.2.2,
    [AC_DEFINE(HAVE_OPENEXR,1,[define if you have OpenEXR >=1.2.2 installed.])
     with_OpenEXR=yes
     PACKAGES_USED="$PACKAGES_USED OpenEXR"],
    [AC_MSG_WARN([OpenEXR not found; disabling OpenEXR support])
     with_OpenEXR=no
    ])
fi

# OpenSlide
AC_ARG_WITH([openslide],
  AS_HELP_STRING([--without-openslide], [build without OpenSlide (default: test)]))

if test x"$with_openslide" != x"no"; then
  PKG_CHECK_MODULES(OPENSLIDE, [openslide >= 3.4.0],
    [AC_DEFINE(HAVE_OPENSLIDE_3_4,1,[define if you have OpenSlide >= 3.4.0 installed.])
     AC_DEFINE(HAVE_OPENSLIDE,1,[define if you have OpenSlide >= 3.3.0 installed.])
     with_openslide=yes
     PACKAGES_USED="$PACKAGES_USED openslide"],
    [AC_MSG_NOTICE([OpenSlide >= 3.4.0 not found; checking for >= 3.3.0])
     PKG_CHECK_MODULES(OPENSLIDE, [openslide >= 3.3.0],
     [AC_DEFINE(HAVE_OPENSLIDE,1,[define if you have OpenSlide >= 3.3.0 installed.])
      with_openslide=yes
      PACKAGES_USED="$PACKAGES_USED openslide"],
     [AC_MSG_WARN([OpenSlide >= 3.3.0 not found; disabling virtual slide support])
      with_openslide=no
     ])
    ])
fi

# matio
AC_ARG_WITH([matio], 
  AS_HELP_STRING([--without-matio], [build without matio (default: test)]))

if test x"$with_matio" != "xno"; then
  PKG_CHECK_MODULES(MATIO, matio,
    [AC_DEFINE(HAVE_MATIO,1,[define if you have matio installed.])
     with_matio=yes
     PACKAGES_USED="$PACKAGES_USED matio"],
    [AC_MSG_WARN([matio not found; disabling matio support])
     with_matio=no
    ])
fi

# cfitsio
AC_ARG_WITH([cfitsio], 
  AS_HELP_STRING([--without-cfitsio], [build without cfitsio (default: test)]))

if test x"$with_cfitsio" != "xno"; then
  PKG_CHECK_MODULES(CFITSIO, cfitsio,
    [AC_DEFINE(HAVE_CFITSIO,1,[define if you have cfitsio installed.])
     with_cfitsio=yes
     PACKAGES_USED="$PACKAGES_USED cfitsio"],
    [AC_MSG_WARN([cfitsio not found; disabling cfitsio support])
     with_cfitsio=no
    ])
fi

# libwebp
AC_ARG_WITH([libwebp], 
  AS_HELP_STRING([--without-libwebp], [build without libwebp (default: test)]))

if test x"$with_libwebp" != "xno"; then
  PKG_CHECK_MODULES(LIBWEBP, libwebp,
    [AC_DEFINE(HAVE_LIBWEBP,1,[define if you have libwebp installed.])
     with_libwebp=yes
     PACKAGES_USED="$PACKAGES_USED libwebp"],
    [AC_MSG_WARN([libwebp not found; disabling libwebp support])
     with_libwebp=no
    ])
fi

# pangoft2
AC_ARG_WITH([pangoft2], 
  AS_HELP_STRING([--without-pangoft2], 
    [build without pangoft2 (default: test)]))

if test x"$with_pangoft2" != "xno"; then
  PKG_CHECK_MODULES(PANGOFT2, pangoft2,
    [AC_DEFINE(HAVE_PANGOFT2,1,[define if you have pangoft2 installed.])
     with_pangoft2=yes
     PACKAGES_USED="$PACKAGES_USED pangoft2"
    ],
    [AC_MSG_WARN([pangoft2 not found; disabling pangoft2 support])
     with_pangoft2=no
    ])
fi

# install vips8 python
AC_ARG_ENABLE([pyvips8],
  AS_HELP_STRING([--enable-pyvips8],
    [install vips8 Python overrides (default: test)]),
  [enable_pyvips8=$enableval], 
  [enable_pyvips8="auto"])

if test "x$enable_pyvips8" = "xauto"; then
  PKG_CHECK_EXISTS([pygobject-3.0 >= 3.12.0],
    [enable_pyvips8=yes],
    [AC_MSG_WARN([pygobject-3.0 not found; disabling vips8 python support])
     enable_pyvips8=no
    ]
  )
fi

if test x"$enable_pyvips8" = x"yes"; then
  AM_PATH_PYTHON(2.7,,
    [enable_pyvips8=no
     AC_MSG_WARN([Python not found; disabling vips8 Python binding])]
  )
fi

if test x"$enable_pyvips8" = x"yes"; then
  PKG_CHECK_MODULES(PYGOBJECT, [pygobject-3.0 >= 3.12.0])
  pyoverridesdir="\$(pyexecdir)/gi/overrides"
  AC_SUBST(pyoverridesdir)
fi

AM_CONDITIONAL(ENABLE_PYVIPS8, test x"$enable_pyvips8" = x"yes")

# hmm, these don't have .pc files on ubuntu 5.10, how odd
FIND_ZIP(
  [with_zip=yes],
  [AC_MSG_WARN([libz not found; disabling ZIP support])
   with_zip=no
  ])

# look for TIFF with pkg-config ... fall back to our tester
# pkgconfig support for libtiff starts with libtiff-4
AC_ARG_WITH([tiff], 
  AS_HELP_STRING([--without-tiff], [build without libtiff (default: test)]))

if test x"$with_tiff" != "xno"; then
  PKG_CHECK_MODULES(TIFF, libtiff-4,
    [AC_DEFINE(HAVE_TIFF,1,[define if you have libtiff installed.])
     with_tiff="yes (pkg-config libtiff-4)"
     PACKAGES_USED="$PACKAGES_USED libtiff-4"],
    [FIND_TIFF(
     with_tiff="yes (found by search)",
     [AC_MSG_WARN([libtiff not found; disabling TIFF support])
      with_tiff=no
     ])
    ])
fi

# look for PNG with pkg-config ... fall back to our tester
AC_ARG_WITH([png], 
  AS_HELP_STRING([--without-png], [build without libpng (default: test)]))

if test x"$with_png" != "xno"; then
  PKG_CHECK_MODULES(PNG, libpng >= 1.2.9, 
    [AC_DEFINE(HAVE_PNG,1,[define if you have libpng installed.])
     with_png="yes (pkg-config libpng >= 1.2.9)"
     PACKAGES_USED="$PACKAGES_USED libpng"],
    [FIND_PNG(
     with_png="yes (found by search)",
     [AC_MSG_WARN([libpng not found; disabling PNG support])
      with_png=no
     ])
    ])
fi

FIND_JPEG(
  [with_jpeg=yes
   EXTRA_LIBS_USED="$EXTRA_LIBS_USED -ljpeg"],
  [AC_MSG_WARN([libjpeg not found; disabling JPEG support])
   with_jpeg=no
  ])

# JPEG extension parameters available in libjpeg-turbo >=1.5.0, mozjpeg >=3.0
if test x"$with_jpeg" = "xyes"; then
  AC_MSG_CHECKING([for JPEG extension parameters])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <stdio.h>
    #include <jpeglib.h>
  ]], [[
    J_BOOLEAN_PARAM test;
  ]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_JPEG_EXT_PARAMS],1,[libjpeg has extension parameters])
  ], [
    AC_MSG_RESULT([no])
  ])
fi

# libexif
AC_ARG_WITH([libexif], 
  AS_HELP_STRING([--without-libexif], [build without libexif (default: test)]))

if test x"$with_libexif" != "xno"; then
  PKG_CHECK_MODULES(EXIF, libexif >= 0.6,
    [AC_DEFINE(HAVE_EXIF,1,[define if you have libexif >= 0.6 installed.])
     with_libexif=yes
     PACKAGES_USED="$PACKAGES_USED libexif"],
    [AC_MSG_WARN([libexif >= 0.6 not found; disabling exif support])
     with_libexif=no
    ])
fi

# some libexif packages need include <libexif/poop.h>, some just <poop.h>
# how annoying
if test x"$with_libexif" != "xno"; then
  # cppflags not cflags because we want the preproc to see the -I as well
  save_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="$EXIF_CFLAGS $CPPFLAGS"
  AC_CHECK_HEADER(exif-data.h,
    AC_DEFINE(UNTAGGED_EXIF,1,[libexif includes don't need libexif prefix]))
  CPPFLAGS=$save_CPPFLAGS
fi

# make python binding?
AC_ARG_WITH([python], 
  AS_HELP_STRING([--without-python], 
    [build without vips7 Python bindings (default: test)]))

if test x"$with_python" != x"no"; then
  if test x"$enable_cxx" = x"no"; then
    # if C++ is off, we can't do Python
    with_python=no
    AC_MSG_WARN([C++ is off, disabling vips7 Python binding])
  fi
fi

if test x"$with_python" != x"no"; then
  AM_PATH_PYTHON(2.7,,
    [with_python=no
     AC_MSG_WARN([Python not found; disabling vips7 Python binding])]
  )
fi

if test x"$with_python" != x"no"; then
  AM_CHECK_PYTHON_HEADERS(,
    [with_python=no
     AC_MSG_WARN([Python headers not found; disabling vips7 Python binding])])
fi

# we don't check for swig: we include the generated bindings in the
# distribution

if test x"$with_python" != x"no"; then
  AM_CONDITIONAL(HAVE_PYTHON, true)
  with_python=yes
else
  AM_CONDITIONAL(HAVE_PYTHON, false)
fi

# Gather all up for VIPS_CFLAGS, VIPS_INCLUDES, VIPS_LIBS 
# sort includes to get longer, more specific dirs first
# helps, for example, selecting graphicsmagick over imagemagick
VIPS_CFLAGS=`for i in $VIPS_CFLAGS $GTHREAD_CFLAGS $REQUIRED_CFLAGS $PANGOFT2_CFLAGS $GSF_CFLAGS $FFTW_CFLAGS $MAGICK_CFLAGS $PNG_CFLAGS $EXIF_CFLAGS $MATIO_CFLAGS $CFITSIO_CFLAGS $LIBWEBP_CFLAGS $OPENEXR_CFLAGS $OPENSLIDE_CFLAGS $ORC_CFLAGS $TIFF_CFLAGS $LCMS_CFLAGS 
do 
	echo $i 
done | sort -ru`
VIPS_CFLAGS=`echo $VIPS_CFLAGS`
VIPS_CFLAGS="$VIPS_DEBUG_FLAGS $VIPS_CFLAGS"
VIPS_INCLUDES="$PNG_INCLUDES $TIFF_INCLUDES $ZIP_INCLUDES $JPEG_INCLUDES" 
VIPS_LIBS="$MAGICK_LIBS $PNG_LIBS $TIFF_LIBS $ZIP_LIBS $JPEG_LIBS $GTHREAD_LIBS $REQUIRED_LIBS $PANGOFT2_LIBS $GSF_LIBS $FFTW_LIBS $ORC_LIBS $LCMS_LIBS $OPENEXR_LIBS $OPENSLIDE_LIBS $CFITSIO_LIBS $LIBWEBP_LIBS $MATIO_LIBS $EXIF_LIBS -lm"

AC_SUBST(VIPS_LIBDIR)

AC_SUBST(VIPS_CFLAGS)
AC_SUBST(VIPS_INCLUDES)
AC_SUBST(VIPS_LIBS)
AC_SUBST(PACKAGES_USED)
AC_SUBST(EXTRA_LIBS_USED)

# needed by test/variables.sh.in
# :( what's a better way to do this, argh
TOP_SRCDIR=$ac_pwd
AC_SUBST(TOP_SRCDIR)

AC_OUTPUT([
	vips.pc
	vipsCC.pc
	vips-cpp.pc
	Makefile 
	libvips/include/vips/version.h 
	libvips/include/Makefile 
	libvips/include/vips/Makefile 
	libvips/Makefile 
	libvips/arithmetic/Makefile 
	libvips/colour/Makefile 
	libvips/conversion/Makefile 
	libvips/convolution/Makefile 
	libvips/deprecated/Makefile 
	libvips/foreign/Makefile 
	libvips/freqfilt/Makefile 
	libvips/histogram/Makefile 
	libvips/draw/Makefile 
	libvips/iofuncs/Makefile 
	libvips/morphology/Makefile 
	libvips/mosaicing/Makefile 
	libvips/create/Makefile 
	libvips/resample/Makefile 
	libvips/video/Makefile 
	libvipsCC/include/Makefile 
	libvipsCC/include/vips/Makefile 
	libvipsCC/Makefile 
	cplusplus/include/Makefile 
	cplusplus/include/vips/Makefile 
	cplusplus/Makefile 
	tools/Makefile 
	tools/batch_crop 
	tools/batch_image_convert 
	tools/batch_rubber_sheet 
	tools/light_correct 
	tools/shrink_width 
	python/Makefile 
	test/Makefile 
	test/variables.sh
	swig/Makefile 
	swig/vipsCC/Makefile 
	man/Makefile
	doc/Makefile
	doc/libvips-docs.xml
	po/Makefile.in
])

AC_MSG_RESULT([
* build options
native win32:				$vips_os_win32
native OS X:				$vips_os_darwin
open files in binary mode: 		$vips_binary_open
enable debug:				$enable_debug
build deprecated components:		$enable_deprecated
build docs with gtkdoc:			$enable_gtk_doc
gobject introspection: 			$found_introspection
build vips7 Python binding:		$with_python
install vips8 Python overrides:		$enable_pyvips8
  (requires pygobject-3.12.0 or later)

* optional dependencies
use fftw3 for FFT: 			$with_fftw
Magick package: 			$with_magickpackage
file import with libMagick: 		$with_magick
accelerate loops with orc: 		$with_orc
  (requires orc-0.4.11 or later)
ICC profile support with lcms: 		$with_lcms
file import with OpenEXR: 		$with_OpenEXR
file import with OpenSlide:		$with_openslide
  (requires openslide-3.3.0 or later)
file import with matio: 		$with_matio
file import with cfitsio: 		$with_cfitsio
file import/export with libwebp:	$with_libwebp
text rendering with pangoft2: 		$with_pangoft2
file import/export with libpng: 	$with_png
  (requires libpng-1.2.9 or later)
file import/export with libtiff:	$with_tiff
file import/export with libjpeg:	$with_jpeg
image pyramid export:			$with_gsf
  (requires libgsf-1 1.14.27 or later)
use libexif to load/save JPEG metadata: $with_libexif
])
