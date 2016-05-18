dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_GIFLIB[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ---------------------------------------------------
dnl
dnl Find GIFLIB libraries and headers
dnl
dnl Put compile stuff in GIFLIB_INCLUDES
dnl Put link stuff in GIFLIB_LIBS
dnl Define HAVE_GIFLIB if found.
dnl
AC_DEFUN([FIND_GIFLIB], [
AC_REQUIRE([AC_PATH_XTRA])

GIFLIB_INCLUDES=""
GIFLIB_LIBS=""

AC_ARG_WITH(giflib, 
  AS_HELP_STRING([--without-giflib], [build without giflib (default: test)]))
# Treat --without-giflib like --without-giflib-includes --without-giflib-libraries.
if test "$with_giflib" = "no"; then
  GIFLIB_INCLUDES=no
  GIFLIB_LIBS=no
fi

AC_ARG_WITH(giflib-includes,
  AS_HELP_STRING([--with-giflib-includes=DIR], [giflib includes are in DIR]),
  GIFLIB_INCLUDES="-I$withval")
AC_ARG_WITH(giflib-libraries,
  AS_HELP_STRING([--with-giflib-libraries=DIR], [giflib libraries are in DIR]),
  GIFLIB_LIBS="-L$withval -lgif")

AC_MSG_CHECKING(for giflib)

# Look for gif_lib.h 
if test "$GIFLIB_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <gif_lib.h>],[int a;],[
    GIFLIB_INCLUDES=""
  ], [
    # gif_lib.h is not in the standard search path, try
    # $prefix
    giflib_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <gif_lib.h>],[int a;],[
      GIFLIB_INCLUDES="-I${prefix}/include"
    ], [
      GIFLIB_INCLUDES="no"
    ])

    INCLUDES=$giflib_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$GIFLIB_LIBS" = ""; then
  giflib_save_LIBS="$LIBS"
  giflib_save_INCLUDES="$INCLUDES"

  LIBS="-lgif $LIBS"
  INCLUDES="$GIFLIB_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <gif_lib.h>],[DGifSlurp(0)], [
    GIFLIB_LIBS="-lgif"
  ], [
    # giflib is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <gif_lib.h>],[DGifSlurp(0)], [
      GIFLIB_LIBS="-L${prefix}/lib -lgif"
    ], [
      GIFLIB_LIBS=no
    ])
  ])

  LIBS="$giflib_save_LIBS"
  INCLUDES="$giflib_save_INCLUDES"
fi

AC_SUBST(GIFLIB_LIBS)
AC_SUBST(GIFLIB_INCLUDES)

# Print a helpful message
giflib_libraries_result="$GIFLIB_LIBS"
giflib_includes_result="$GIFLIB_INCLUDES"

if test x"$giflib_libraries_result" = x""; then
  giflib_libraries_result="in default path"
fi
if test x"$giflib_includes_result" = x""; then
  giflib_includes_result="in default path"
fi

if test "$giflib_libraries_result" = "no"; then
  giflib_libraries_result="(none)"
fi
if test "$giflib_includes_result" = "no"; then
  giflib_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $giflib_libraries_result, headers $giflib_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$GIFLIB_INCLUDES" != "no" && test "$GIFLIB_LIBS" != "no"; then
  AC_DEFINE(HAVE_GIFLIB,1,[Define if you have giflib libraries and header files.])
  $1
else
  GIFLIB_INCLUDES=""
  GIFLIB_LIBS=""
  $2
fi

])dnl
