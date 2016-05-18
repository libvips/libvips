dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_TIFF[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find TIFF libraries and headers
dnl
dnl Put compile stuff in TIFF_INCLUDES
dnl Put link stuff in TIFF_LIBS
dnl Define HAVE_TIFF if found
dnl
AC_DEFUN([FIND_TIFF], [
AC_REQUIRE([AC_PATH_XTRA])

TIFF_INCLUDES=""
TIFF_LIBS=""

AC_ARG_WITH(tiff, 
  AS_HELP_STRING([--without-tiff], [build without libtiff (default: test)]))
# Treat --without-tiff like --without-tiff-includes --without-tiff-libraries.
if test "$with_tiff" = "no"; then
  TIFF_INCLUDES=no
  TIFF_LIBS=no
fi

AC_ARG_WITH(tiff-includes,
  AS_HELP_STRING([--with-tiff-includes=DIR], [libtiff includes are in DIR]),
  TIFF_INCLUDES="-I$withval")
AC_ARG_WITH(tiff-libraries,
  AS_HELP_STRING([--with-tiff-libraries=DIR], [libtiff libraries are in DIR]),
  TIFF_LIBS="-L$withval -ltiff")

AC_MSG_CHECKING(for TIFF)

# Look for tiff.h 
if test "$TIFF_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <tiff.h>],[int a;],[
    TIFF_INCLUDES=""
  ], [
    # tiff.h is not in the standard search path, try
    # $prefix
    tiff_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <tiff.h>],[int a;],[
      TIFF_INCLUDES="-I${prefix}/include"
    ], [
      TIFF_INCLUDES="no"
    ])

    INCLUDES=$tiff_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$TIFF_LIBS" = ""; then
  tiff_save_LIBS="$LIBS"
  tiff_save_INCLUDES="$INCLUDES"

  LIBS="-ltiff -lm $LIBS"
  INCLUDES="$TIFF_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <tiff.h>],[TIFFGetVersion()], [
    TIFF_LIBS="-ltiff"
  ], [
    # libtiff is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <tiff.h>],[TIFFGetVersion()], [
      TIFF_LIBS="-L${prefix}/lib -ltiff"
    ], [
      TIFF_LIBS=no
    ])
  ])

  LIBS="$tiff_save_LIBS"
  INCLUDES="$tiff_save_INCLUDES"
fi

AC_SUBST(TIFF_LIBS)
AC_SUBST(TIFF_INCLUDES)

# Print a helpful message
tiff_libraries_result="$TIFF_LIBS"
tiff_includes_result="$TIFF_INCLUDES"

if test x"$tiff_libraries_result" = x""; then
  tiff_libraries_result="in default path"
fi
if test x"$tiff_includes_result" = x""; then
  tiff_includes_result="in default path"
fi

if test "$tiff_libraries_result" = "no"; then
  tiff_libraries_result="(none)"
fi
if test "$tiff_includes_result" = "no"; then
  tiff_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $tiff_libraries_result, headers $tiff_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$TIFF_INCLUDES" != "no" && test "$TIFF_LIBS" != "no"; then
  AC_DEFINE(HAVE_TIFF,1,[Define if you have tiff libraries and header files.])
  $1
else
  TIFF_INCLUDES=""
  TIFF_LIBS=""
  $2
fi

])dnl
