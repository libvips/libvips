# Process this file with autoconf to produce a configure script.

# also update the version number in the m4 macros below

AC_INIT([vips], [8.11.0], [vipsip@jiscmail.ac.uk])
# required for gobject-introspection
AC_PREREQ(2.62)

# gobject-introspection recommends -Wno-portability
# foreign stops complaints about a missing README (we use README.md instead)
# and missing INSTALL (the standard Gnu INSTALL is not very useful)
# subdir-objects lets us have dummy.cc in a subdir
AM_INIT_AUTOMAKE([-Wno-portability foreign subdir-objects])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# user-visible library versioning
m4_define([vips_major_version], [8])
m4_define([vips_minor_version], [11])
m4_define([vips_micro_version], [0])
m4_define([vips_version],
          [vips_major_version.vips_minor_version.vips_micro_version])

VIPS_MAJOR_VERSION=vips_major_version()
VIPS_MINOR_VERSION=vips_minor_version()
VIPS_MICRO_VERSION=vips_micro_version()
VIPS_VERSION=vips_version()
VIPS_VERSION_STRING="$VIPS_VERSION-$(date -u -r $srcdir/ChangeLog)"

# packages add to these as we find them
VIPS_CFLAGS=""
VIPS_INCLUDES=""
VIPS_LIBS=""

# libtool library versioning ... not user-visible (except as part of the
# library file name) and does not correspond to major/minor/micro above

# rules:
# sources changed: increment revision
# binary interface changed: increment current, reset revision to 0
#   binary interface changes backwards compatible?: increment age
#   binary interface changes not backwards compatible?: reset age to 0

LIBRARY_CURRENT=55
LIBRARY_REVISION=0
LIBRARY_AGE=13

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

# remove the '(disabled, use --enable-introspection to enable)'
# suffix from the found_introspection variable
if test "x$found_introspection" != x"yes"; then
  found_introspection=no
fi

# gir needs a list of source files to scan for introspection
#
# build with a glob and a list of files to exclude from scanning
# see also IGNORE_HFILES in doc/Makefile.am
introspection_sources=$(cd $srcdir/libvips ; find . -path ./deprecated -prune -o -name dummy.c -prune -o -name introspect.c -prune -o \( -name "*.c" -o -name "*.cpp" \) -print)
for name in $introspection_sources; do
  vips_introspection_sources="$vips_introspection_sources $name"
done

# add headers that form the public vips8 API .. don't do a find and exclude,
# we end up excluding almost everything argh
headers="\
        basic.h \
        vips.h \
        object.h \
        image.h \
        error.h \
        foreign.h \
        freqfilt.h \
        interpolate.h \
        header.h \
        histogram.h \
        operation.h \
        enumtypes.h \
        conversion.h \
        arithmetic.h \
        colour.h \
        convolution.h \
        create.h \
        draw.h \
        morphology.h \
        mosaicing.h \
        type.h \
        rect.h \
        resample.h \
        memory.h \
        region.h"

for name in $headers; do
  vips_introspection_sources="$vips_introspection_sources include/vips/$name"
done

AC_SUBST(vips_introspection_sources)

AC_CANONICAL_HOST

AC_DEFINE_UNQUOTED(G_LOG_DOMAIN, "VIPS", [Domain for glib logging messages.])

m4_define([debug_default], [no])
AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--enable-debug=@<:@no/minimum/yes@:>@],
    [turn on debugging @<:@default=debug_default()@:>@]),,
  enable_debug=debug_default())

if test x"$enable_debug" = x"yes"; then
  VIPS_DEBUG_FLAGS="-DDEBUG_FATAL -DDEBUG_LEAK"
else
  VIPS_DEBUG_FLAGS="-DG_DISABLE_CAST_CHECKS"

  if test x"$enable_debug" = x"no"; then
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
fi
AC_DEFINE_UNQUOTED(ENABLE_DEPRECATED,$VIPS_ENABLE_DEPRECATED,[define to build deprecated components])
AM_CONDITIONAL(ENABLE_DEPRECATED, [test x"$enable_deprecated" = x"yes"])

# this gets pasted into version.h as a #define
AC_SUBST(VIPS_ENABLE_DEPRECATED)

AC_MSG_CHECKING([for -mms-bitfields support])
case "$host_os" in
  mingw*)
    # makes gcc use win native alignment
    # GCC >= 4.7 and Clang >= 11 does this automatically, see:
    # https://gitlab.gnome.org/GNOME/glib/-/merge_requests/1510#note_841637
    VIPS_CFLAGS="-mms-bitfields $VIPS_CFLAGS"
    AC_MSG_RESULT([yes])
    ;;
  *)
    AC_MSG_RESULT([no])
    ;;
esac

# set the default directory for ICC profiles
case "$host_os" in
  darwin*)
    profile_dir="/Library/ColorSync/Profiles"
    ;;
  mingw*)
    # need double escapes since this will get pasted into a #define in a C
    # header ... the C:\Windows is usually overwritten with the result of
    # GetWindowsDirectoryW()
    profile_dir="C:\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\color"
    ;;
  *)
    profile_dir="/usr/share/color/icc"
    ;;
esac
AC_DEFINE_UNQUOTED(VIPS_ICC_DIR,"$profile_dir",[default directory for ICC profiles])

# we want largefile support, if possible
AC_SYS_LARGEFILE

# we use libtool
LT_INIT

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S

AC_ARG_WITH([doxygen], 
  AS_HELP_STRING([--without-doxygen], [build without doxygen (default: test)]))

if test x"$with_doxygen" != x"no"; then
  AC_CHECK_PROGS([DOXYGEN], [doxygen])
  if test "$DOXYGEN"; then
    with_doxygen=yes
  else
    AC_MSG_WARN([doxygen not found; C++ docs will not be generated])
    with_doxygen=no
  fi
fi
AM_CONDITIONAL(HAVE_DOXYGEN, [test x"$with_doxygen" = x"yes"])

# we need a fully expanded version of $libdir
# without this we get something like
#    define VIPS_LIBDIR ${exec_prefix}/lib
# argh
test x"$prefix" = x"NONE" && prefix=$ac_default_prefix
test x"$exec_prefix" = x"NONE" && exec_prefix='${prefix}'

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

# we need to disable some features on some known-bad gcc versions
# these will be "" for clang etc. 
#
# I couldn't get this to work, mysterious! do it ourselves
# 
# AX_CHECK_COMPILE_FLAG([-dumpversion],
#   [ax_gcc_version_option=yes],
#   [ax_gcc_version_option=no]
# )
AC_MSG_CHECKING([for $CC version])
GCC_VERSION=""
version=$($CC -dumpversion)
if test $? = 0; then 
  GCC_VERSION=$version
  AC_MSG_RESULT([$GCC_VERSION])
else
  AC_MSG_RESULT([-dumpversion not supported])
fi

GCC_VERSION_MAJOR=$(echo $GCC_VERSION | cut -d'.' -f1)
GCC_VERSION_MINOR=$(echo $GCC_VERSION | cut -d'.' -f2)
GCC_VERSION_PATCH=$(echo $GCC_VERSION | cut -d'.' -f3)

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
AC_C_RESTRICT
AX_GCC_VAR_ATTRIBUTE(vector_size)
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# g++/gcc 4.x and 5.x have rather broken vector support ... 5.4.1 seems to
# work, but 5.4.0 fails to even compile
AC_MSG_CHECKING([for $CC with working vector support])
if test x"$GCC_VERSION_MAJOR" != x"4" -a x"$GCC_VERSION_MAJOR" != x"5"; then
  AC_MSG_RESULT([yes])
else
  ax_cv_have_var_attribute_vector_size=no
  AC_MSG_RESULT([no])
fi

# we need to be able to shuffle vectors in C++
if test x"$ax_cv_have_var_attribute_vector_size" = x"yes"; then
  AC_MSG_CHECKING([for C++ vector shuffle])
  AC_LANG_PUSH([C++])
  AC_TRY_COMPILE([
    typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
  ],[
    v4f f; f[3] = 99;
  ],[
    AC_MSG_RESULT([yes])
    have_vector_shuffle=yes
  ], [
    AC_MSG_RESULT([no])
    have_vector_shuffle=no
  ])
  AC_LANG_POP([C++])

  if test x"$have_vector_shuffle" = x"yes"; then
    AC_DEFINE_UNQUOTED(HAVE_VECTOR_SHUFFLE, 1,
      [define if your C++ can shuffle vectors])
  fi
fi

# we also need to be able to mix vector and scalar arithmetic
if test x"$have_vector_shuffle" = x"yes"; then
  AC_MSG_CHECKING([for C++ vector arithmetic])
  AC_LANG_PUSH([C++])
  AC_TRY_COMPILE([
    typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
  ],[
    v4f f = {1, 2, 3, 4}; f *= 12.0; 
    v4f g = {5, 6, 7, 8}; f = g > 0 ? g : -1 * g;
  ],[
    AC_MSG_RESULT([yes])
    have_vector_arith=yes
  ], [
    AC_MSG_RESULT([no])
    have_vector_arith=no
  ])
  AC_LANG_POP([C++])
fi

# gcc 7.2 seems to work, but then gets confused by signed constants in 
# templates
if test x"$have_vector_arith" = x"yes"; then
  AC_MSG_CHECKING([for C++ signed constants in vector templates])
  AC_LANG_PUSH([C++])
  AC_TRY_COMPILE([
    typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
    template <typename T>
    static void
    h( v4f B )
    {
        v4f f;
        f = -1 * B;
    }
  ],[
  ],[
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_RESULT([no])
    have_vector_arith=no
  ])
  AC_LANG_POP([C++])

  if test x"$have_vector_arith" = x"yes"; then
    AC_DEFINE_UNQUOTED(HAVE_VECTOR_ARITH, 1,
      [define if your C++ can mix vector and scalar arithmetic])
  fi
fi

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getcwd gettimeofday getwd memset munmap putenv realpath strcasecmp strchr strcspn strdup strerror strrchr strspn vsnprintf realpath mkstemp mktemp random rand sysconf atexit _aligned_malloc posix_memalign memalign])
AC_CHECK_LIB(m,cbrt,[AC_DEFINE(HAVE_CBRT,1,[have cbrt() in libm.])])
AC_CHECK_LIB(m,hypot,[AC_DEFINE(HAVE_HYPOT,1,[have hypot() in libm.])])
AC_CHECK_LIB(m,atan2,[AC_DEFINE(HAVE_ATAN2,1,[have atan2() in libm.])])

# have to have these parts of glib ... we need glib 2.15 for gio
PKG_CHECK_MODULES(REQUIRED, glib-2.0 >= 2.40 gmodule-no-export-2.0 gobject-2.0 gio-2.0)
PACKAGES_USED="$PACKAGES_USED glib-2.0 gmodule-no-export-2.0 gobject-2.0 gio-2.0"

# from 2.62 we have datetime
PKG_CHECK_MODULES(DATE_TIME_FORMAT_ISO8601, glib-2.0 >= 2.62,
  [AC_DEFINE(HAVE_DATE_TIME_FORMAT_ISO8601,1,
            [define if your glib has g_date_time_format_iso8601().]
   )
  ],
  [:
  ]
)

VIPS_CFLAGS="$VIPS_CFLAGS $GIO_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $GIO_LIBS"

# if available, we use pthread_setattr_default_np() to raise the per-thread 
# stack size ... musl (libc on Alpine), for example, has a very small stack per 
# thread by default
save_pthread_LIBS="$LIBS"
save_pthread_CFLAGS="$CFLAGS"
LIBS="$LIBS $REQUIRED_LIBS"
CFLAGS="$CFLAGS $REQUIRED_CFLAGS"
AC_CHECK_FUNC(pthread_setattr_default_np,
  [AC_DEFINE(HAVE_PTHREAD_DEFAULT_NP,1,[have pthread_setattr_default_np().])
  ]
)
LIBS="$save_pthread_LIBS"
CFLAGS="$save_pthread_CFLAGS"

# from 2.48 we have g_uint_checked_mul() etc.
PKG_CHECK_MODULES(HAVE_CHECKED_MUL, glib-2.0 >= 2.48,
  [AC_DEFINE(HAVE_CHECKED_MUL,1,[define if your glib has checked multiply.])
  ],
  [:
  ]
)

AC_MSG_CHECKING([whether to build dynamic modules])

AC_ARG_ENABLE([modules], 
  AS_HELP_STRING([--disable-modules], [disable dynamic modules (default: enabled)]))

gmodule_supported_bool=false
gmodule_supported_flag=no
gmodule_with_flag=yes

if test x"$enable_modules" = x"no"; then
  AC_MSG_RESULT(no)
else
  AC_MSG_RESULT(yes)
  AC_MSG_CHECKING(whether dynamic modules work)
  gmodule_supported_bool=`$PKG_CONFIG gmodule-no-export-2.0 --variable gmodule_supported`
  if $gmodule_supported_bool; then
    gmodule_supported_flag=yes
    gmodule_with_flag='module'
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi

# check for gtk-doc
GTK_DOC_CHECK([1.14],[--flavour no-tmpl])

# we need expat ... the .pc file for expat is only available
# for recent linuxes, so we fall back to AM_WITH_EXPAT
PKG_CHECK_MODULES(EXPAT, expat,
  [expat_found=yes
   PACKAGES_USED="$PACKAGES_USED expat"
  ],
  [AM_WITH_EXPAT
  ]
)

if test x"$expat_found" = x"no"; then
  exit 1
fi

VIPS_CFLAGS="$VIPS_CFLAGS $EXPAT_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $EXPAT_LIBS"

# optional supporting libraries

AC_ARG_WITH([gsf], 
  AS_HELP_STRING([--without-gsf], [build without libgsf-1 (default: test)]))

# libgsf-1 1.14.21 crashes 
# .27 is known to work well
# .26 seems OK but has not been tested much
# not sure about 22-25
if test x"$with_gsf" != x"no"; then
  PKG_CHECK_MODULES(GSF, libgsf-1 >= 1.14.26,
    [AC_DEFINE(HAVE_GSF,1,[define if you have libgsf-1 installed.])
     with_gsf=yes
     PACKAGES_USED="$PACKAGES_USED libgsf-1"
    ],
    [AC_MSG_WARN([libgsf-1 not found; disabling dzsave support]) 
     with_gsf=no
    ]
  )

  # zip64 and deflate-level came in .31
  PKG_CHECK_MODULES(GSF_ZIP64, libgsf-1 >= 1.14.31,
    [AC_DEFINE(HAVE_GSF_ZIP64,1,[define if your libgsf supports zip64.])
     AC_DEFINE(HAVE_GSF_DEFLATE_LEVEL,1,
               [define if your libgsf supports deflate-level.])
    ],
    [:
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $GSF_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $GSF_LIBS"

AC_ARG_WITH([fftw], 
  AS_HELP_STRING([--without-fftw], [build without fftw (default: test)]))

if test x"$with_fftw" != x"no"; then
  PKG_CHECK_MODULES(FFTW, fftw3,
    [AC_DEFINE(HAVE_FFTW,1,[define if you have fftw3 installed.])
     with_fftw=yes
     PACKAGES_USED="$PACKAGES_USED fftw3"
    ],
    [AC_MSG_WARN([fftw not found; disabling fftw support]) 
     with_fftw=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $FFTW_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $FFTW_LIBS"

# ImageMagick 
AC_ARG_WITH([magick], 
  AS_HELP_STRING([--without-magick], [build without libMagic (default: test)]),
    [with_magick=$withval],
    [with_magick=$gmodule_with_flag])

# libMagic as a dynamically loadable module
AS_IF([test x"$with_magick" = x"module"],
  [with_magick_module=$gmodule_supported_flag],
  [with_magick_module=no])

AC_ARG_WITH([magickpackage], 
  AS_HELP_STRING([--with-magickpackage], 
    [magickpackage to use (default: MagickCore; try GraphicsMagick to build against gm instead)]))

# set the default magick package ... very old imagemagicks called it
# ImageMagick
if test x"$with_magickpackage" = x""; then
  PKG_CHECK_MODULES(MAGICK_WAND, MagickCore,
    [with_magickpackage=MagickCore
    ],
    [PKG_CHECK_MODULES(IMAGE_MAGICK, ImageMagick,
       [with_magickpackage=ImageMagick
       ],
       [AC_MSG_WARN([neither MagickCore nor ImageMagick found; disabling Magick support])
        with_magick=no
        with_magick_module=no
       ]
     )
    ]
  )
fi

# we have a separate loader for magick7 with fewer ifdef
# options; only test for features on the magick6 case

magick_version=
if test x"$with_magick" != x"no"; then
  PKG_CHECK_MODULES(MAGICK, $with_magickpackage >= 7.0,  
    [AC_DEFINE(HAVE_MAGICK7,1,[define if you have libMagick7 installed.])
     with_magick=yes
     magick7=yes
     magick_version=magick7
     AS_IF([test x"$with_magick_module" = x"no"],
       [PACKAGES_USED="$PACKAGES_USED $with_magickpackage"])
    ],
    [PKG_CHECK_MODULES(MAGICK, $with_magickpackage,  
       [AC_DEFINE(HAVE_MAGICK6,1,[define if you have libMagick6 installed.])
        with_magick=yes
        magick6=yes
        magick_version=magick6
        AS_IF([test x"$with_magick_module" = x"no"],
          [PACKAGES_USED="$PACKAGES_USED $with_magickpackage"])
       ],
       [AC_MSG_WARN([$with_magickpackage not found; disabling Magick support])
        with_magick=no
        with_magick_module=no
       ]
     )
    ]  
  )
else
  with_magick=no
  with_magick_module=no
  magick6=no
  magick_version=none
  with_magickpackage=none
fi

if test x"$magick6" = x"yes"; then
  # do we have number_scenes in image_info ... imagemagick uses this
  save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $MAGICK_CFLAGS"
  AC_CHECK_MEMBER([struct _ImageInfo.number_scenes],
    AC_DEFINE(HAVE_NUMBER_SCENES,1,
              [define if your magick has ImageInfo.number_scenes.]),
    [],
    [#include <magick/api.h>])
  CFLAGS="$save_CFLAGS"
fi

if test x"$magick6" = x"yes"; then
  # the magick6 API varies a lot between magick versions, and between GM and
  # IM
  save_LIBS="$LIBS"
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS([InheritException AcquireExceptionInfo SetImageProperty SetImageExtent AcquireImage GetVirtualPixels ResetImageProfileIterator ResetImageAttributeIterator ResetImagePropertyIterator MagickCoreGenesis SetImageOption BlobToStringInfo OptimizePlusImageLayers OptimizeImageTransparency])
  LIBS="$save_LIBS"
fi

if test x"$magick6" = x"yes"; then
  save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $MAGICK_CFLAGS"

  # the range of ColorspaceType has expanded several times
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [#include <magick/api.h>],
      [ColorspaceType colorspace = CMYColorspace]
    )],
    [AC_DEFINE(HAVE_CMYCOLORSPACE,1,
         [define if your Magick has CMYColorspace.])
    ]
  )

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [#include <magick/api.h>],
      [ColorspaceType colorspace = HCLpColorspace]
    )],
    [AC_DEFINE(HAVE_HCLPCOLORSPACE,1,
         [define if your Magick has HCLpColorspace.])
    ]
  )

  # GetImageMagick() takes two args under GM, three under IM
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [#include <magick/api.h>],
      [(void)GetImageMagick(NULL, 0, NULL)]
    )],
    [AC_DEFINE(HAVE_GETIMAGEMAGICK3,1,
         [define if your GetImageMagick() takes three arguments.])
    ]
  )

  CFLAGS="$save_CFLAGS"
fi

# have flags to turn load and save off independently ... some people will want
# save but not load, for example
AC_ARG_ENABLE([magickload], 
  AS_HELP_STRING([--disable-magickload], 
                 [disable libMagic load (default: enabled)]))

AC_ARG_ENABLE([magicksave], 
  AS_HELP_STRING([--disable-magicksave], 
                 [disable libMagic save (default: enabled)]))

if test x"$enable_magicksave" != x"yes"; then
  # we need ImportImagePixels ... GM is missing this sadly
  save_LIBS="$LIBS"
  LIBS="$LIBS $MAGICK_LIBS"
  AC_CHECK_FUNCS(ImportImagePixels,[
     AC_DEFINE(HAVE_IMPORTIMAGEPIXELS,1,
               [define if you have ImportImagePixels.])
   ],[]
  )
  AC_CHECK_FUNCS(ImagesToBlob,[
     AC_DEFINE(HAVE_IMAGESTOBLOB,1,
               [define if you have ImagesToBlob.])
   ],[]
  ) 
  LIBS="$save_LIBS"
fi

if test x"$with_magick" != x"no"; then
  if test x"$enable_magickload" != x"no"; then
    AC_DEFINE(ENABLE_MAGICKLOAD,1,[define to enable load with libMagick])
    enable_magickload=yes
  fi

  if test x"$enable_magicksave" != x"no"; then
    AC_DEFINE(ENABLE_MAGICKSAVE,1,[define to enable save with libMagick])
    enable_magicksave=yes
  fi
else
  enable_magickload=no
  enable_magicksave=no
fi

AS_IF([test x"$with_magick_module" = x"yes"],
  [AC_DEFINE([MAGICK_MODULE], [1], [define to build libMagic as a dynamically loadable module.])],
  [VIPS_CFLAGS="$VIPS_CFLAGS $MAGICK_CFLAGS"
   VIPS_LIBS="$VIPS_LIBS $MAGICK_LIBS"])
AM_CONDITIONAL(MAGICK_MODULE, [test x"$with_magick_module" = x"yes"])

# orc
AC_ARG_WITH([orc], 
  AS_HELP_STRING([--without-orc], [build without orc (default: test)]))

if test x"$with_orc" != x"no"; then
  # we use loadpw etc.
  PKG_CHECK_MODULES(ORC, orc-0.4 >= 0.4.11,
    [AC_DEFINE(HAVE_ORC,1,[define if you have orc-0.4.11 or later installed.])
     with_orc=yes
     PACKAGES_USED="$PACKAGES_USED orc-0.4"
     save_LIBS="$LIBS"
     LIBS="$LIBS $ORC_LIBS"
     AC_CHECK_FUNCS(orc_program_get_error,
       AC_DEFINE(HAVE_ORC_PROGRAM_GET_ERROR,1,
              [define if your orc has orc_program_get_error.]))
     LIBS="$save_LIBS"
    ],
    [AC_MSG_WARN([orc-0.4.11 or later not found; disabling orc support])
     with_orc=no
    ]
  )
fi

# orc 0.4.30+ works with cf-protection, but 0.4.30 has a bug with multiple
# definitions of OrcTargetPowerPCFlags, so insist on 0.4.31
if test x"$with_orc" = x"yes"; then
  PKG_CHECK_MODULES(ORC_CF_PROTECTION, orc-0.4 >= 0.4.31,
    [AC_DEFINE(HAVE_ORC_CF_PROTECTION,1,
               [define if your orc works with cf-protection.]
     )
    ],
    [:
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $ORC_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $ORC_LIBS"

# lcms ... refuse to use lcms1
AC_ARG_WITH([lcms], 
  AS_HELP_STRING([--without-lcms], [build without lcms (default: test)]))

if test x"$with_lcms" != x"no"; then
  PKG_CHECK_MODULES(LCMS, lcms2,
    [AC_DEFINE(HAVE_LCMS2,1,[define if you have lcms2 installed.])
     with_lcms="yes (lcms2)"
     PACKAGES_USED="$PACKAGES_USED lcms2"
    ],
    [AC_MSG_WARN([lcms2 not found; disabling ICC profile support])
     with_lcms=no
    ]
  )
fi

# we need a conditional for this to only compile in fallback profiles if lcms
# is detected
AM_CONDITIONAL(ENABLE_LCMS, [test x"$with_lcms" != x"no"])

VIPS_CFLAGS="$VIPS_CFLAGS $LCMS_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $LCMS_LIBS"

# OpenEXR
AC_ARG_WITH([OpenEXR], 
  AS_HELP_STRING([--without-OpenEXR], [build without OpenEXR (default: test)]))

# require 1.2.2 since 1.2.1 has a broken ImfCloseTiledInputFile()
if test x"$with_OpenEXR" != x"no"; then
  PKG_CHECK_MODULES(OPENEXR, OpenEXR >= 1.2.2,
    [AC_DEFINE(HAVE_OPENEXR,1,[define if you have OpenEXR >=1.2.2 installed.])
     with_OpenEXR=yes
     PACKAGES_USED="$PACKAGES_USED OpenEXR"
    ],
    [AC_MSG_WARN([OpenEXR not found; disabling OpenEXR support])
     with_OpenEXR=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $OPENEXR_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $OPENEXR_LIBS"

# nifti
AC_ARG_WITH([nifti],
  AS_HELP_STRING([--without-nifti], [build without nifti (default: test)]))

if test x"$with_nifti" != x"no"; then
  FIND_NIFTI([
     with_nifti=yes
    ],[
     with_nifti=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $NIFTI_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $NIFTI_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $NIFTI_LIBS"

# jpeg-xl
AC_ARG_WITH([libjxl],
  AS_HELP_STRING([--without-libjxl], [build without libjxl (default: test)]),
  [with_libjxl=$withval],
  [with_libjxl=$gmodule_with_flag])

# libjxl as a dynamically loadable module
AS_IF([test x"$with_libjxl" = x"module"],
  [with_libjxl_module=$gmodule_supported_flag],
  [with_libjxl_module=no])

if test x"$with_libjxl" != x"no"; then
  PKG_CHECK_MODULES(LIBJXL, libjxl_threads >= 0.3.7 libjxl >= 0.3.7,
    [AC_DEFINE(HAVE_LIBJXL,1,
       [define if you have libjxl >= 0.3.7 installed.])
     with_libjxl=yes
     AS_IF([test x"$with_libjxl_module" = x"no"],
       [PACKAGES_USED="$PACKAGES_USED libjxl"])
    ],
    [AC_MSG_WARN([libjxl not found; disabling libjxl support])
     with_libjxl=no
     with_libjxl_module=no
    ]
  )
fi

AS_IF([test x"$with_libjxl_module" = x"yes"],
  [AC_DEFINE([LIBJXL_MODULE], [1], [define to build libjxl as a dynamically loadable module.])],
  [VIPS_CFLAGS="$VIPS_CFLAGS $LIBJXL_CFLAGS"
   VIPS_LIBS="$VIPS_LIBS $LIBJXL_LIBS"])
AM_CONDITIONAL(LIBJXL_MODULE, [test x"$with_libjxl_module" = x"yes"])

# openjpeg
AC_ARG_WITH([libopenjp2],
  AS_HELP_STRING([--without-libopenjp2], 
                 [build without libopenjp2 (default: test)]))

# 2.4 is the first one to have working threading and tiling
if test x"$with_libopenjp2" != x"no"; then
  PKG_CHECK_MODULES(LIBOPENJP2, libopenjp2 >= 2.4,
    [AC_DEFINE(HAVE_LIBOPENJP2,1,
       [define if you have libopenjp2 >=2.4 installed.])
     with_libopenjp2=yes
     PACKAGES_USED="$PACKAGES_USED libopenjp2"
    ],
    [AC_MSG_WARN([libopenjp2 not found; disabling libopenjp2 support])
     with_libopenjp2=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $LIBOPENJP2_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $LIBOPENJP2_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $LIBOPENJP2_LIBS"

# libheif
AC_ARG_WITH([heif], 
  AS_HELP_STRING([--without-heif], [build without libheif (default: test)]),
  [with_heif=$withval],
  [with_heif=$gmodule_with_flag])

# libheif as a dynamically loadable module
AS_IF([test x"$with_heif" = x"module"],
  [with_heif_module=$gmodule_supported_flag],
  [with_heif_module=no])

if test x"$with_heif" != x"no"; then
  PKG_CHECK_MODULES(HEIF, libheif >= 1.3.0,
    [with_heif=yes
     have_h265_decoder=`$PKG_CONFIG libheif --variable builtin_h265_decoder`
     have_avif_decoder=`$PKG_CONFIG libheif --variable builtin_avif_decoder`
     # test for !=no so that we work for older libheif which does not have
     # this variable
     if test x"$have_h265_decoder" != x"no" -o x"$have_avif_decoder" = x"yes"; then
        AC_DEFINE(HAVE_HEIF_DECODER,1,
             [define if your libheif has decode support.])
     fi
     have_h265_encoder=`$PKG_CONFIG libheif --variable builtin_h265_encoder`
     have_avif_encoder=`$PKG_CONFIG libheif --variable builtin_avif_encoder`
     if test x"$have_h265_encoder" != x"no" -o x"$have_avif_encoder" = x"yes"; then
        AC_DEFINE(HAVE_HEIF_ENCODER,1,
             [define if your libheif has encode support.])
     fi
     AS_IF([test x"$with_heif_module" = x"no"],
       [PACKAGES_USED="$PACKAGES_USED libheif"])
    ],
    [AC_MSG_WARN([libheif >= 1.3.0 not found; disabling HEIF support])
     pkg-config --exists --print-errors "libheif >= 1.3.0"
     with_heif=no
     with_heif_module=no
     have_h265_decoder=
     have_h265_encoder=
     have_avif_decoder=
     have_avif_encoder=
    ]
  )
fi

AS_IF([test x"$with_heif_module" = x"yes"],
  [AC_DEFINE([HEIF_MODULE], [1], [define to build libheif as a dynamically loadable module.])],
  [VIPS_CFLAGS="$VIPS_CFLAGS $HEIF_CFLAGS"
   VIPS_LIBS="$VIPS_LIBS $HEIF_LIBS"])
AM_CONDITIONAL(HEIF_MODULE, [test x"$with_heif_module" = x"yes"])

# color profile support added in 1.3.3
if test x"$with_heif" = x"yes"; then
  save_LIBS="$LIBS"
  LIBS="$LIBS $HEIF_LIBS"
  AC_CHECK_FUNCS(heif_image_handle_get_raw_color_profile,[
     AC_DEFINE(HAVE_HEIF_COLOR_PROFILE,1,
               [define if you have heif_image_handle_get_raw_color_profile.])
   ],[]
  )
  LIBS="$save_LIBS"
fi

# heif_main_brand added in 1.4.0, but heif_avif appeared in 1.7 ... just check
# the libheif version number since testing for enums is annoying
if test x"$with_heif" = x"yes"; then
  PKG_CHECK_MODULES(HEIF_AVIF, libheif >= 1.7.0, [
    AC_DEFINE(HAVE_HEIF_AVIF,1,[define if you have heif_avif.])
  ], [
  ])
fi

# heif_decoding_options.convert_hdr_to_8bit added in 1.7.0
if test x"$with_heif" = x"yes"; then
  save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $HEIF_CFLAGS"
  AC_CHECK_MEMBER([struct heif_decoding_options.convert_hdr_to_8bit],[
     AC_DEFINE(HAVE_HEIF_DECODING_OPTIONS_CONVERT_HDR_TO_8BIT,1,
               [define if you have heif_decoding_options.convert_hdr_to_8bit])
   ],[],
   [#include <libheif/heif.h>])
  CFLAGS="$save_CFLAGS"
fi

# pdfium
AC_ARG_WITH([pdfium],
  AS_HELP_STRING([--without-pdfium], [build without pdfium (default: test)]))

# pick 4200 as the starting version number ... no reason, really, it'd
# probably work with much older versions
if test x"$with_pdfium" != x"no"; then
  PKG_CHECK_MODULES(PDFIUM, pdfium >= 4200, [
    AC_DEFINE(HAVE_PDFIUM,1,[define if you have pdfium > 4200.])
    if test x"$with_poppler" != x"no"; then
      AC_MSG_WARN([PDFium found, disabling poppler])
      with_poppler=no
    fi
    with_pdfium=yes
    PACKAGES_USED="$PACKAGES_USED pdfium"
  ], [
    with_pdfium=no
  ])
fi

VIPS_CFLAGS="$VIPS_CFLAGS $PDFIUM_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $PDFIUM_LIBS"

# poppler
AC_ARG_WITH([poppler],
  AS_HELP_STRING([--without-poppler], [build without poppler (default: test)]),
  [with_poppler=$withval],
  [with_poppler=$gmodule_with_flag])

# poppler as a dynamically loadable module
AS_IF([test x"$with_poppler" = x"module"],
  [with_poppler_module=$gmodule_supported_flag],
  [with_poppler_module=no])

if test x"$with_poppler" != x"no"; then
  PKG_CHECK_MODULES(POPPLER, [poppler-glib >= 0.16.0 cairo >= 1.2], [
    AC_DEFINE(HAVE_POPPLER,1,[define if you have poppler-glib >= 0.16.0 and cairo >= 1.2 installed.])
    with_poppler=yes
    AS_IF([test x"$with_poppler_module" = x"no"],
      [PACKAGES_USED="$PACKAGES_USED poppler-glib cairo"])
  ], [
    AC_MSG_WARN([poppler-glib >= 0.16.0 or cairo >= 1.2 not found; disabling PDF load via poppler])
    with_poppler=no
    with_poppler_module=no
  ])
fi

AS_IF([test x"$with_poppler_module" = x"yes"],
  [AC_DEFINE([POPPLER_MODULE], [1], [define to build poppler as a dynamically loadable module.])],
  [VIPS_CFLAGS="$VIPS_CFLAGS $POPPLER_CFLAGS"
   VIPS_LIBS="$VIPS_LIBS $POPPLER_LIBS"])
AM_CONDITIONAL(POPPLER_MODULE, [test x"$with_poppler_module" = x"yes"])

# librsvg
AC_ARG_WITH([rsvg],
  AS_HELP_STRING([--without-rsvg], [build without rsvg (default: test)]))

# 2.40.3 so we get the UNLIMITED open flag
if test x"$with_rsvg" != x"no"; then
  PKG_CHECK_MODULES(RSVG, [librsvg-2.0 >= 2.40.3 cairo >= 1.2], [
    AC_DEFINE(HAVE_RSVG,1,[define if you have librsvg-2.0 >= 2.40.3 and cairo >= 1.2 installed.])
    with_rsvg=yes
    PACKAGES_USED="$PACKAGES_USED librsvg-2.0 cairo"
  ], [
    AC_MSG_WARN([librsvg-2.0 >= 2.40.3 or cairo >= 1.2 not found; disabling SVG load via rsvg])
    with_rsvg=no
  ])
fi

VIPS_CFLAGS="$VIPS_CFLAGS $RSVG_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $RSVG_LIBS"

# zlib
# some platforms, like macosx, are missing the .pc files for zlib, so
# we fall back to FIND_ZLIB
AC_ARG_WITH([zlib], 
  AS_HELP_STRING([--without-zlib], [build without zlib (default: test)]))

if test x"$with_zlib" != x"no"; then
  PKG_CHECK_MODULES(ZLIB, zlib >= 0.4,
    [AC_DEFINE(HAVE_ZLIB,1,[define if you have zlib installed.])
     with_zlib=yes
     PACKAGES_USED="$PACKAGES_USED zlib"
    ],
    [FIND_ZLIB(
       [with_zlib="yes (found by search)"
       ], 
       [AC_MSG_WARN([zlib not found; disabling SVGZ buffer support])
        with_zlib=no
       ]
     )
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $ZLIB_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $ZLIB_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $ZLIB_LIBS"

# OpenSlide
AC_ARG_WITH([openslide],
  AS_HELP_STRING([--without-openslide], 
    [build without OpenSlide (default: test)]),
  [with_openslide=$withval],
  [with_openslide=$gmodule_with_flag])

# OpenSlide as a dynamically loadable module
AS_IF([test x"$with_openslide" = x"module"],
  [with_openslide_module=$gmodule_supported_flag],
  [with_openslide_module=no])

if test x"$with_openslide" != x"no"; then
  PKG_CHECK_MODULES(OPENSLIDE, [openslide >= 3.4.0],
    [AC_DEFINE(HAVE_OPENSLIDE_3_4,1,[define if you have OpenSlide >= 3.4.0 installed.])
     AC_DEFINE(HAVE_OPENSLIDE,1,[define if you have OpenSlide >= 3.3.0 installed.])
     with_openslide=yes
     AS_IF([test x"$with_openslide_module" = x"no"],
       [PACKAGES_USED="$PACKAGES_USED openslide"])
    ],
    [AC_MSG_NOTICE([OpenSlide >= 3.4.0 not found; checking for >= 3.3.0])
     PKG_CHECK_MODULES(OPENSLIDE, [openslide >= 3.3.0],
       [AC_DEFINE(HAVE_OPENSLIDE,1,[define if you have OpenSlide >= 3.3.0 installed.])
        with_openslide=yes
        AS_IF([test x"$with_openslide_module" = x"no"],
          [PACKAGES_USED="$PACKAGES_USED openslide"])
       ],
       [AC_MSG_WARN([OpenSlide >= 3.3.0 not found; disabling virtual slide support])
        with_openslide=no
        with_openslide_module=no
       ]
     )
    ]
  )
fi

AS_IF([test x"$with_openslide_module" = x"yes"],
  [AC_DEFINE([OPENSLIDE_MODULE], [1], [define to build OpenSlide as a dynamically loadable module.])],
  [VIPS_CFLAGS="$VIPS_CFLAGS $OPENSLIDE_CFLAGS"
   VIPS_LIBS="$VIPS_LIBS $OPENSLIDE_LIBS"])
AM_CONDITIONAL(OPENSLIDE_MODULE, [test x"$with_openslide_module" = x"yes"])

# matio
AC_ARG_WITH([matio], 
  AS_HELP_STRING([--without-matio], [build without matio (default: test)]))

if test x"$with_matio" != x"no"; then
  PKG_CHECK_MODULES(MATIO, matio,
    [AC_DEFINE(HAVE_MATIO,1,[define if you have matio installed.])
     with_matio=yes
     PACKAGES_USED="$PACKAGES_USED matio"
    ],
    [AC_MSG_WARN([matio not found; disabling matio support])
     with_matio=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $MATIO_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $MATIO_LIBS"

# not external libraries, but have options to disable them, helps to
# reduce attack surface

AC_ARG_WITH([nsgif], 
  AS_HELP_STRING([--without-nsgif], [build without nsgif load (default: with)]))

if test x"$with_nsgif" != x"no"; then
  AC_DEFINE(HAVE_NSGIF,1,[define to build nsgif load support.])
  with_nsgif=yes
fi

AM_CONDITIONAL(ENABLE_NSGIF, [test x"$with_nsgif" = x"yes"])

AC_ARG_WITH([ppm], 
  AS_HELP_STRING([--without-ppm], [build without ppm (default: with)]))

if test x"$with_ppm" != x"no"; then
  AC_DEFINE(HAVE_PPM,1,[define to build ppm support.])
  with_ppm=yes
fi

AC_ARG_WITH([analyze], 
  AS_HELP_STRING([--without-analyze], [build without analyze (default: with)]))

if test x"$with_analyze" != x"no"; then
  AC_DEFINE(HAVE_ANALYZE,1,[define to build analyze support.])
  with_analyze=yes
fi

AC_ARG_WITH([radiance], 
  AS_HELP_STRING([--without-radiance], [build without radiance (default: with)]))

if test x"$with_radiance" != x"no"; then
  AC_DEFINE(HAVE_RADIANCE,1,[define to build radiance support.])
  with_radiance=yes
fi

# cfitsio
AC_ARG_WITH([cfitsio], 
  AS_HELP_STRING([--without-cfitsio], [build without cfitsio (default: test)]))

if test x"$with_cfitsio" != x"no"; then
  PKG_CHECK_MODULES(CFITSIO, cfitsio,
    [AC_DEFINE(HAVE_CFITSIO,1,[define if you have cfitsio installed.])
     with_cfitsio=yes
     PACKAGES_USED="$PACKAGES_USED cfitsio"
    ],
    [AC_MSG_WARN([cfitsio not found; disabling cfitsio support])
     with_cfitsio=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $CFITSIO_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $CFITSIO_LIBS"

# libwebp ... target 0.6+ to reduce complication
# webp has the stuff for handling metadata in two separate libraries  -- we
# insit on having all of them
AC_ARG_WITH([libwebp], 
  AS_HELP_STRING([--without-libwebp], [build without libwebp (default: test)]))

if test x"$with_libwebp" != x"no"; then
  PKG_CHECK_MODULES(LIBWEBP, libwebp >= 0.6 libwebpmux >= 0.6 libwebpdemux >= 0.6,
    [AC_DEFINE(HAVE_LIBWEBP,1,[define if you have libwebp/libwebpmux/libwebpdemux installed.])
     with_libwebp=yes
     PACKAGES_USED="$PACKAGES_USED libwebp libwebpmux libwebpdemux"
    ],
    [AC_MSG_WARN([libwebp, mux, demux not found; disabling WEBP support])
     with_libwebp=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $LIBWEBP_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $LIBWEBP_LIBS"

# pangocairo for text rendering
AC_ARG_WITH([pangocairo], 
  AS_HELP_STRING([--without-pangocairo], 
    [build without pangocairo (default: test)]))

if test x"$with_pangocairo" != x"no"; then
  PKG_CHECK_MODULES(PANGOCAIRO, pangocairo,
    [AC_DEFINE(HAVE_PANGOCAIRO,1,[define if you have pangocairo installed.])
     with_pangocairo=yes
     PACKAGES_USED="$PACKAGES_USED pangocairo"
    ],
    [AC_MSG_WARN([pangocairo not found; disabling pangocairo support])
     with_pangocairo=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $PANGOCAIRO_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $PANGOCAIRO_LIBS"

# font file support with fontconfig
AC_ARG_WITH([fontconfig], 
  AS_HELP_STRING([--without-fontconfig], 
    [build without fontconfig (default: test)]))

if test x"$with_pangocairo" != x"no" -a x"$with_fontconfig" != x"no"; then
  PKG_CHECK_MODULES(FONTCONFIG, fontconfig,
    [AC_DEFINE(HAVE_FONTCONFIG,1,[define if you have fontconfig installed.])
     with_fontconfig=yes
     PACKAGES_USED="$PACKAGES_USED fontconfig"
    ],
    [AC_MSG_WARN([fontconfig not found; disabling fontconfig support])
     with_fontconfig=no
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $FONTCONFIG_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $FONTCONFIG_LIBS"

# look for TIFF with pkg-config ... fall back to our tester
# pkgconfig support for libtiff starts with libtiff-4
AC_ARG_WITH([tiff], 
  AS_HELP_STRING([--without-tiff], [build without libtiff (default: test)]))

if test x"$with_tiff" != x"no"; then
  PKG_CHECK_MODULES(TIFF, libtiff-4,
    [AC_DEFINE(HAVE_TIFF,1,[define if you have libtiff installed.])
     with_tiff="yes (pkg-config libtiff-4)"
     PACKAGES_USED="$PACKAGES_USED libtiff-4"
    ],
    [FIND_TIFF(
       with_tiff="yes (found by search)",
       [AC_MSG_WARN([libtiff not found; disabling TIFF support])
        with_tiff=no
       ]
     )
    ]
  )
fi

# ZSTD and WEBP in TIFF added in libtiff 4.0.10
if test x"$with_tiff" != x"no"; then
  save_INCLUDES="$INCLUDES"
  INCLUDES="$INCLUDES $TIFF_INCLUDES"
  AC_CHECK_DECL(COMPRESSION_WEBP,[
      AC_DEFINE(HAVE_TIFF_COMPRESSION_WEBP,1,[define if your libtiff has webp.])
    ],[
    ],[
      [#include <tiffio.h>]
    ]
  )
  INCLUDES="$save_INCLUDES"
fi

VIPS_CFLAGS="$VIPS_CFLAGS $TIFF_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $TIFF_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $TIFF_LIBS"

# Look for libspng first
# 0.6.1 uses "libspng.pc", git master libspng uses "spng.pc"
AC_ARG_WITH([libspng], 
  AS_HELP_STRING([--without-libspng], [build without libspng (default: test)]))

if test x"$with_libspng" != x"no"; then
  PKG_CHECK_MODULES(SPNG, libspng >= 0.6,
    [AC_DEFINE(HAVE_SPNG,1,[define if you have libspng installed.])
     with_libspng=yes
     PACKAGES_USED="$PACKAGES_USED libspng"
    ],
    [PKG_CHECK_MODULES(SPNG, spng >= 0.6,
      [AC_DEFINE(HAVE_SPNG,1,[define if you have libspng installed.])
       with_libspng=yes
       PACKAGES_USED="$PACKAGES_USED spng"
      ],
      [with_libspng=no
      ]
     )
    ]
  )
fi

VIPS_CFLAGS="$VIPS_CFLAGS $SPNG_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $SPNG_LIBS"

# look for PNG with pkg-config ... fall back to our tester
# we can have both PNG and SPNG enabled, with SPNG for read and PNG for
# write
AC_ARG_WITH([png], 
  AS_HELP_STRING([--without-png], [build without libpng (default: test)]))

if test x"$with_png" != x"no"; then
  PKG_CHECK_MODULES(PNG, libpng >= 1.2.9, 
    [AC_DEFINE(HAVE_PNG,1,[define if you have libpng installed.])
     with_png="yes (pkg-config libpng >= 1.2.9)"
     PACKAGES_USED="$PACKAGES_USED libpng"
    ],
    [FIND_PNG(
       [with_png="yes (found by search)"
       ],
       [AC_MSG_WARN([libpng not found; disabling PNG support])
        with_png=no
       ]
     )
    ]
  )
fi

if test x"$with_png" != x"no"; then
  save_LIBS="$LIBS"
  save_CFLAGS="$CFLAGS"
  LIBS="$PNG_LIBS $LIBS"
  CFLAGS="$PNG_INCLUDES $CFLAGS"
  AC_CHECK_FUNCS(png_set_chunk_malloc_max,
    AC_DEFINE(HAVE_PNG_SET_CHUNK_MALLOC_MAX,1,
              [define if your libpng has png_set_chunk_malloc_max.]))
  LIBS="$save_LIBS"
  CFLAGS="$save_CFLAGS"
fi

VIPS_CFLAGS="$VIPS_CFLAGS $PNG_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $PNG_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $PNG_LIBS"

# look for libimagequant with pkg-config (only if libpng is enabled)
AC_ARG_WITH([imagequant],
  AS_HELP_STRING([--without-imagequant], [build without imagequant (default: test)]))

if test x"$with_imagequant" != x"no" && test x"$with_png" != x"no"; then
  PKG_CHECK_MODULES(IMAGEQUANT, imagequant,
    [AC_DEFINE(HAVE_IMAGEQUANT,1,[define if you have imagequant installed.])
     with_imagequant=yes
     PACKAGES_USED="$PACKAGES_USED imagequant"
    ],
    [AC_MSG_WARN([libimagequant not found; disabling 8bpp PNG support])
     with_imagequant=no
    ]
  )
else
  with_imagequant=no
fi

VIPS_CFLAGS="$VIPS_CFLAGS $IMAGEQUANT_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $IMAGEQUANT_LIBS"

# look for libjpeg with pkg-config ... fall back to our tester
AC_ARG_WITH([jpeg], 
  AS_HELP_STRING([--without-jpeg], [build without libjpeg (default: test)]))

if test x"$with_jpeg" != x"no"; then
  PKG_CHECK_MODULES(JPEG, libjpeg,
    [AC_DEFINE(HAVE_JPEG,1,[define if you have libjpeg installed.])
     with_jpeg="yes (pkg-config)"
     PACKAGES_USED="$PACKAGES_USED libjpeg"
    ],
    [FIND_JPEG(
       [with_jpeg="yes (found by search)"
        EXTRA_LIBS_USED="$EXTRA_LIBS_USED -ljpeg"
       ],
       [AC_MSG_WARN([libjpeg not found; disabling JPEG support])
        with_jpeg=no
       ]
     )
    ]
  )
fi

# features like trellis quant are exposed as extension parameters ...
# mozjpeg 3.2 and later have #define JPEG_C_PARAM_SUPPORTED, but we must 
# work with earlier versions
if test x"$with_jpeg" != x"no"; then
  save_LIBS="$LIBS"
  save_CFLAGS="$CFLAGS"
  LIBS="$JPEG_LIBS $LIBS"
  CFLAGS="$JPEG_INCLUDES $CFLAGS"
  AC_CHECK_FUNCS(jpeg_c_bool_param_supported,
    AC_DEFINE(HAVE_JPEG_EXT_PARAMS,1,
              [define if your libjpeg has extension parameters.]))
  LIBS="$save_LIBS"
  CFLAGS="$save_CFLAGS"
fi

VIPS_CFLAGS="$VIPS_CFLAGS $JPEG_CFLAGS"
VIPS_INCLUDES="$VIPS_INCLUDES $JPEG_INCLUDES"
VIPS_LIBS="$VIPS_LIBS $JPEG_LIBS"

# libexif
AC_ARG_WITH([libexif], 
  AS_HELP_STRING([--without-libexif], [build without libexif (default: test)]))

if test x"$with_libexif" != x"no"; then
  PKG_CHECK_MODULES(EXIF, libexif >= 0.6,
    [AC_DEFINE(HAVE_EXIF,1,[define if you have libexif >= 0.6 installed.])
     with_libexif=yes
     PACKAGES_USED="$PACKAGES_USED libexif"
    ],
    [AC_MSG_WARN([libexif >= 0.6 not found; disabling exif support])
     with_libexif=no
    ]
  )
fi

# some libexif packages need include <libexif/poop.h>, some just <poop.h>
# how annoying
if test x"$with_libexif" != x"no"; then
  # cppflags not cflags because we want the preproc to see the -I as well
  save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$EXIF_CFLAGS $CPPFLAGS"
  AC_CHECK_HEADER(exif-data.h,
    AC_DEFINE(UNTAGGED_EXIF,1,[libexif includes don't need libexif prefix]))
  CPPFLAGS="$save_CPPFLAGS"
fi

VIPS_CFLAGS="$VIPS_CFLAGS $EXIF_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $EXIF_LIBS"

# fuzzing
AC_ARG_VAR([LIB_FUZZING_ENGINE],
           [fuzzing library, e.g. /path/to/libFuzzer.a])
if test x"$LIB_FUZZING_ENGINE" = x; then
  LIB_FUZZING_ENGINE="libstandaloneengine.a"
fi

VIPS_CFLAGS="$VIPS_CFLAGS $VIPS_DEBUG_FLAGS $REQUIRED_CFLAGS"
VIPS_LIBS="$VIPS_LIBS $REQUIRED_LIBS -lm"

# autoconf hates multi-line AC_SUBST so we have to have another copy of this
# thing
VIPS_CONFIG="\
enable debug: $enable_debug, \
enable deprecated library components: $enable_deprecated, \
enable modules: $gmodule_supported_flag, \
enable docs with gtkdoc: $enable_gtk_doc, \
gobject introspection:  $found_introspection, \
RAD load/save: $with_radiance, \
Analyze7 load/save: $with_analyze, \
PPM load/save: $with_ppm, \
GIF load:  $with_nsgif, \
generate C++ docs: $with_doxygen, \
use fftw3 for FFT: $with_fftw, \
accelerate loops with orc: $with_orc, \
ICC profile support with lcms: $with_lcms, \
zlib: $with_zlib, \
text rendering with pangocairo: $with_pangocairo, \
font file support with fontconfig: $with_fontconfig, \
EXIF metadata support with libexif: $with_libexif, \
JPEG load/save with libjpeg: $with_jpeg, \
JXL load/save with libjxl: $with_libjxl (dynamic module: $with_libjxl_module), \
JPEG2000 load/save with libopenjp2: $with_libopenjp2, \
PNG load with libspng: $with_libspng, \
PNG load/save with libpng: $with_png, \
8bpp PNG quantisation: $with_imagequant, \
TIFF load/save with libtiff: $with_tiff, \
image pyramid save: $with_gsf, \
HEIC/AVIF load/save with libheif: $with_heif (dynamic module: $with_heif_module), \
WebP load/save with libwebp: $with_libwebp, \
PDF load with PDFium:  $with_pdfium, \
PDF load with poppler-glib: $with_poppler (dynamic module: $with_poppler_module), \
SVG load with librsvg-2.0: $with_rsvg, \
EXR load with OpenEXR: $with_OpenEXR, \
slide load with OpenSlide: $with_openslide (dynamic module: $with_openslide_module), \
Matlab load with matio: $with_matio, \
NIfTI load/save with niftiio: $with_nifti, \
FITS load/save with cfitsio: $with_cfitsio, \
Magick package: $with_magickpackage (dynamic module: $with_magick_module), \
Magick API version: $magick_version, \
load with libMagickCore: $enable_magickload, \
save with libMagickCore: $enable_magicksave"

AC_SUBST(VIPS_LIBDIR)

AC_SUBST(VIPS_CFLAGS)
AC_SUBST(VIPS_INCLUDES)
AC_SUBST(VIPS_LIBS)
AC_SUBST(VIPS_CONFIG)
AC_SUBST(PACKAGES_USED)
AC_SUBST(EXTRA_LIBS_USED)

# needed by test/variables.sh.in
# :( what's a better way to do this, argh
TOP_SRCDIR=$ac_pwd
AC_SUBST(TOP_SRCDIR)

AC_CONFIG_FILES([
        vips.pc
        vips-cpp.pc
        Makefile
        $srcdir/libvips/include/vips/version.h
        libvips/include/Makefile
        libvips/include/vips/Makefile
        libvips/Makefile
        libvips/arithmetic/Makefile
        libvips/colour/Makefile
        libvips/colour/profiles/Makefile
        libvips/conversion/Makefile
        libvips/convolution/Makefile
        libvips/deprecated/Makefile
        libvips/foreign/Makefile
        libvips/foreign/libnsgif/Makefile
        libvips/freqfilt/Makefile
        libvips/histogram/Makefile
        libvips/draw/Makefile
        libvips/iofuncs/Makefile
        libvips/module/Makefile
        libvips/morphology/Makefile
        libvips/mosaicing/Makefile
        libvips/create/Makefile
        libvips/resample/Makefile
        cplusplus/Doxyfile
        cplusplus/include/Makefile
        cplusplus/include/vips/Makefile
        cplusplus/Makefile
        tools/Makefile
        tools/batch_crop
        tools/batch_image_convert
        tools/batch_rubber_sheet
        tools/light_correct
        tools/shrink_width
        test/Makefile
        test/variables.sh
        test/test-suite/Makefile
        test/test-suite/helpers/Makefile
        man/Makefile
        doc/Makefile
        doc/libvips-docs.xml
        po/Makefile.in
        fuzz/Makefile
])
AC_OUTPUT

# also add any new items to VIPS_CONFIG above
AC_MSG_RESULT([dnl
## Build options
enable debug:                           $enable_debug
enable deprecated library components:   $enable_deprecated
enable modules:                         $gmodule_supported_flag
enable C docs with gtkdoc:              $enable_gtk_doc
 (requires gtk-doc 1.14 or later)
gobject introspection:                  $found_introspection
 (requires gobject-introspection 1.30 or later)
RAD load/save:                          $with_radiance
Analyze7 load/save:                     $with_analyze
PPM load/save:                          $with_ppm
GIF load:                               $with_nsgif
generate C++ docs with doxygen:         $with_doxygen

## Optional dependencies
use fftw3 for FFT:                      $with_fftw
accelerate loops with orc:              $with_orc
 (requires orc-0.4.11 or later)
ICC profile support with lcms:          $with_lcms
zlib:                                   $with_zlib
text rendering with pangocairo:         $with_pangocairo
font file support with fontconfig:      $with_fontconfig
EXIF metadata support with libexif:     $with_libexif

## File format support
JPEG load/save with libjpeg:            $with_jpeg
JXL load/save with libjxl:              $with_libjxl (dynamic module: $with_libjxl_module)
JPEG2000 load/save with libopenjp2:     $with_libopenjp2
 (requires libopenjp2 2.4 or later)
PNG load with libspng:                  $with_libspng
 (requires libspng-0.6 or later)
PNG load/save with libpng:              $with_png
 (requires libpng-1.2.9 or later)
8bpp PNG quantisation:                  $with_imagequant
 (requires libimagequant)
TIFF load/save with libtiff:            $with_tiff
image pyramid save:                     $with_gsf
 (requires libgsf-1 1.14.26 or later)
HEIC/AVIF load/save with libheif:       $with_heif (dynamic module: $with_heif_module)
WebP load/save with libwebp:            $with_libwebp
 (requires libwebp, libwebpmux, libwebpdemux 0.6.0 or later)
PDF load with PDFium:                   $with_pdfium
PDF load with poppler-glib:             $with_poppler (dynamic module: $with_poppler_module)
 (requires poppler-glib 0.16.0 or later)
SVG load with librsvg-2.0:              $with_rsvg
 (requires librsvg-2.0 2.34.0 or later)
EXR load with OpenEXR:                  $with_OpenEXR
slide load with OpenSlide:              $with_openslide (dynamic module: $with_openslide_module)
 (requires openslide-3.3.0 or later)
Matlab load with matio:                 $with_matio
NIfTI load/save with niftiio:           $with_nifti
FITS load/save with cfitsio:            $with_cfitsio
Magick package:                         $with_magickpackage (dynamic module: $with_magick_module)
Magick API version:                     $magick_version
load with libMagickCore:                $enable_magickload
save with libMagickCore:                $enable_magicksave
])
