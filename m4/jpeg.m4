dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_JPEG[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find JPEG libraries and headers
dnl
dnl Put compile stuff in JPEG_INCLUDES
dnl Put link stuff in JPEG_LIBS
dnl Define HAVE_JPEG if found
dnl
AC_DEFUN([FIND_JPEG], [
AC_REQUIRE([AC_PATH_XTRA])

JPEG_INCLUDES=""
JPEG_LIBS=""

AC_ARG_WITH(jpeg, 
  AS_HELP_STRING([--without-jpeg], [build without libjpeg (default: test)]))
# Treat --without-jpeg like --without-jpeg-includes --without-jpeg-libraries.
if test "$with_jpeg" = "no"; then
  JPEG_INCLUDES=no
  JPEG_LIBS=no
fi

AC_ARG_WITH(jpeg-includes,
  AS_HELP_STRING([--with-jpeg-includes=DIR], [libjpeg includes are in DIR]),
  JPEG_INCLUDES="-I$withval")
AC_ARG_WITH(jpeg-libraries,
  AS_HELP_STRING([--with-jpeg-libraries=DIR], [libjpeg libraries are in DIR]),
  JPEG_LIBS="-L$withval -ljpeg")

AC_MSG_CHECKING(for JPEG)

# Look for jpeglib.h 
if test "$JPEG_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <stdio.h>
    #include <jpeglib.h>],[int a;],[
    JPEG_INCLUDES=""
  ], [
    # jpeglib.h is not in the standard search path, try
    # $prefix
    jpeg_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <stdio.h>
      #include <jpeglib.h>],[int a;],[
      JPEG_INCLUDES="-I${prefix}/include"
    ], [
      JPEG_INCLUDES="no"
    ])

    INCLUDES=$jpeg_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$JPEG_LIBS" = ""; then
  jpeg_save_LIBS="$LIBS"
  jpeg_save_INCLUDES="$INCLUDES"

  LIBS="-ljpeg $LIBS"
  INCLUDES="$JPEG_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <stdio.h>
    #include <jpeglib.h>
  ],[jpeg_abort((void*)0)], [
    JPEG_LIBS="-ljpeg"
  ], [
    # libjpeg is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <stdio.h>
      #include <jpeg.h>
    ],[jpeg_abort((void*)0)], [
      JPEG_LIBS="-L${prefix}/lib -ljpeg"
    ], [
      JPEG_LIBS=no
    ])
  ])

  LIBS="$jpeg_save_LIBS"
  INCLUDES="$jpeg_save_INCLUDES"
fi

AC_SUBST(JPEG_LIBS)
AC_SUBST(JPEG_INCLUDES)

# Print a helpful message
jpeg_libraries_result="$JPEG_LIBS"
jpeg_includes_result="$JPEG_INCLUDES"

if test x"$jpeg_libraries_result" = x""; then
  jpeg_libraries_result="in default path"
fi
if test x"$jpeg_includes_result" = x""; then
  jpeg_includes_result="in default path"
fi

if test "$jpeg_libraries_result" = "no"; then
  jpeg_libraries_result="(none)"
fi
if test "$jpeg_includes_result" = "no"; then
  jpeg_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $jpeg_libraries_result, headers $jpeg_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$JPEG_INCLUDES" != "no" && test "$JPEG_LIBS" != "no"; then
  AC_DEFINE(HAVE_JPEG,1,[Define if you have jpeg libraries and header files.])
  $1
else
  JPEG_INCLUDES=""
  JPEG_LIBS=""
  $2
fi

])dnl
