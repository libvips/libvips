dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_LIBWEBP[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ---------------------------------------------------
dnl
dnl Find webp libraries and headers ... useful for platforms which are missing
dnl the webp .pc file
dnl
dnl Put compile stuff in LIBWEBP_INCLUDES
dnl Put link stuff in LIBWEBP_LIBS
dnl Define HAVE_LIBWEBP if found.
dnl
AC_DEFUN([FIND_LIBWEBP], [
AC_REQUIRE([AC_PATH_XTRA])

LIBWEBP_INCLUDES=""
LIBWEBP_LIBS=""

AC_ARG_WITH(libwebp, 
  AS_HELP_STRING([--without-libwebp], [build without libwebp (default: test)]))
# Treat --without-libwebp like --without-libwebp-includes --without-libwebp-libraries.
if test "$with_libwebp" = "no"; then
  LIBWEBP_INCLUDES=no
  LIBWEBP_LIBS=no
fi

AC_ARG_WITH(libwebp-includes,
  AS_HELP_STRING([--with-libwebp-includes=DIR], [libwebp includes are in DIR]),
  LIBWEBP_INCLUDES="-I$withval")
AC_ARG_WITH(libwebp-libraries,
  AS_HELP_STRING([--with-libwebp-libraries=DIR], [libwebp libraries are in DIR]),
  LIBWEBP_LIBS="-L$withval -lwebp")

AC_MSG_CHECKING(for libwebp)

# Look for webp/decode.h
if test "$LIBWEBP_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <webp/decode.h>],[int a;],[
    LIBWEBP_INCLUDES=""
  ], [
    # webp/decode.h is not in the standard search path, try
    # $prefix
    libwebp_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <webp/decode.h>],[int a;],[
      LIBWEBP_INCLUDES="-I${prefix}/include"
    ], [
      LIBWEBP_INCLUDES="no"
    ])

    INCLUDES=$libwebp_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$LIBWEBP_LIBS" = ""; then
  libwebp_save_LIBS="$LIBS"
  libwebp_save_INCLUDES="$INCLUDES"

  LIBS="-lwebp $LIBS"
  INCLUDES="$LIBWEBP_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <webp/decode.h>],[WebPInitDecoderConfig(0)], [
    LIBWEBP_LIBS="-lwebp"
  ], [
    # libwebp is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <webp/decode.h>],[WebPInitDecoderConfig(0)], [
      LIBWEBP_LIBS="-L${prefix}/lib -lwebp"
    ], [
      LIBWEBP_LIBS=no
    ])
  ])

  LIBS="$libwebp_save_LIBS"
  INCLUDES="$libwebp_save_INCLUDES"
fi

AC_SUBST(LIBWEBP_LIBS)
AC_SUBST(LIBWEBP_INCLUDES)

# Print a helpful message
libwebp_libraries_result="$LIBWEBP_LIBS"
libwebp_includes_result="$LIBWEBP_INCLUDES"

if test x"$libwebp_libraries_result" = x""; then
  libwebp_libraries_result="in default path"
fi
if test x"$libwebp_includes_result" = x""; then
  libwebp_includes_result="in default path"
fi

if test "$libwebp_libraries_result" = "no"; then
  libwebp_libraries_result="(none)"
fi
if test "$libwebp_includes_result" = "no"; then
  libwebp_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $libwebp_libraries_result, headers $libwebp_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$LIBWEBP_INCLUDES" != "no" && test "$LIBWEBP_LIBS" != "no"; then
  AC_DEFINE(HAVE_LIBWEBP,1,[Define if you have libwebp libraries and header files.])
  $1
else
  LIBWEBP_INCLUDES=""
  LIBWEBP_LIBS=""
  $2
fi

])dnl

