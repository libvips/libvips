dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_ZIP[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find ZIP libraries and headers
dnl
dnl Put includes stuff in ZIP_INCLUDES
dnl Put link stuff in ZIP_LIBS
dnl Define HAVE_ZIP if found
dnl
AC_DEFUN([FIND_ZIP], [
AC_REQUIRE([AC_PATH_XTRA])

ZIP_INCLUDES=""
ZIP_LIBS=""

AC_ARG_WITH(zip, 
  AS_HELP_STRING([--without-zip], [build without libx (default: test)]))
# Treat --without-zip like --without-zip-includes --without-zip-libraries.
if test "$with_zip" = "no"; then
  ZIP_INCLUDES=no
  ZIP_LIBS=no
fi

AC_ARG_WITH(zip-includes,
  AS_HELP_STRING([--with-zip-includes=DIR], [libz includes are in DIR]),
  ZIP_INCLUDES="-I$withval")
AC_ARG_WITH(zip-libraries,
  AS_HELP_STRING([--with-zip-libraries=DIR], [libz libraries are in DIR]),
  ZIP_LIBS="-L$withval -lz")

AC_MSG_CHECKING(for ZIP)

# Look for zlib.h 
if test "$ZIP_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <zlib.h>],[int a;],[
    ZIP_INCLUDES=""
  ], [
    # zlib.h is not in the standard search path, try
    # $prefix
    zip_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <zlib.h>],[int a;],[
      ZIP_INCLUDES="-I${prefix}/include"
    ], [
      ZIP_INCLUDES="no"
    ])

    INCLUDES=$zip_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$ZIP_LIBS" = ""; then
  zip_save_LIBS="$LIBS"
  zip_save_INCLUDES="$INCLUDES"

  LIBS="-lz $LIBS"
  INCLUDES="$ZIP_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <zlib.h>],[zlibVersion()], [
    ZIP_LIBS="-lz"
  ], [
    # libz is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <zlib.h>],[zlibVersion()], [
      ZIP_LIBS="-L${prefix}/lib -lz"
    ], [
      ZIP_LIBS=no
    ])
  ])

  LIBS="$zip_save_LIBS"
  INCLUDES="$zip_save_INCLUDES"
fi

AC_SUBST(ZIP_LIBS)
AC_SUBST(ZIP_INCLUDES)

# Print a helpful message
zip_libraries_result="$ZIP_LIBS"
zip_includes_result="$ZIP_INCLUDES"

if test x"$zip_libraries_result" = x""; then
  zip_libraries_result="in default path"
fi
if test x"$zip_includes_result" = x""; then
  zip_includes_result="in default path"
fi

if test "$zip_libraries_result" = "no"; then
  zip_libraries_result="(none)"
fi
if test "$zip_includes_result" = "no"; then
  zip_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $zip_libraries_result, headers $zip_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$ZIP_INCLUDES" != "no" && test "$ZIP_LIBS" != "no"; then
  AC_DEFINE(HAVE_ZIP,1,[Define if you have libz libraries and header files.])
  $1
else
  ZIP_LIBS=""
  ZIP_INCLUDES=""
  $2
fi

])dnl
