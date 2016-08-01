dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_ZLIB[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find zlib libraries and headers ... useful for platforms which are missing
dnl the zlib .pc file
dnl
dnl Put compile stuff in ZLIB_INCLUDES
dnl Put link stuff in ZLIB_LIBS
dnl Define HAVE_ZLIB if found
dnl
AC_DEFUN([FIND_ZLIB], [
AC_REQUIRE([AC_PATH_XTRA])

ZLIB_INCLUDES=""
ZLIB_LIBS=""

AC_ARG_WITH(zlib, 
  AS_HELP_STRING([--without-zlib], [build without zlib (default: test)]))
# Treat --without-zlib like --without-zlib-includes --without-zlib-libraries.
if test "$with_zlib" = "no"; then
  ZLIB_INCLUDES=no
  ZLIB_LIBS=no
fi

AC_ARG_WITH(zlib-includes,
  AS_HELP_STRING([--with-zlib-includes=DIR], [libz includes are in DIR]),
  ZLIB_INCLUDES="-I$withval")
AC_ARG_WITH(zlib-libraries,
  AS_HELP_STRING([--with-zlib-libraries=DIR], [libz libraries are in DIR]),
  ZLIB_LIBS="-L$withval -lz")

AC_MSG_CHECKING(for ZLIB)

# Look for zlib.h 
if test "$ZLIB_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <stdio.h>
    #include <zlib.h>],[int a;],[
    ZLIB_INCLUDES=""
  ], [
    # zlib.h is not in the standard search path, try
    # $prefix
    zlib_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <stdio.h>
      #include <zlib.h>],[int a;],[
      ZLIB_INCLUDES="-I${prefix}/include"
    ], [
      ZLIB_INCLUDES="no"
    ])

    INCLUDES=$zlib_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$ZLIB_LIBS" = ""; then
  zlib_save_LIBS="$LIBS"
  zlib_save_INCLUDES="$INCLUDES"

  LIBS="-lz $LIBS"
  INCLUDES="$ZLIB_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <stdio.h>
    #include <zlib.h>
  ],[z_stream zs;inflateInit2(&zs, 15 | 32)], [
    ZLIB_LIBS="-lz"
  ], [
    # libz is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <stdio.h>
      #include <zlib.h>
    ],[z_stream zs;inflateInit2(&zs, 15 | 32)], [
      ZLIB_LIBS="-L${prefix}/lib -lz"
    ], [
      ZLIB_LIBS=no
    ])
  ])

  LIBS="$zlib_save_LIBS"
  INCLUDES="$zlib_save_INCLUDES"
fi

AC_SUBST(ZLIB_LIBS)
AC_SUBST(ZLIB_INCLUDES)

# Print a helpful message
zlib_libraries_result="$ZLIB_LIBS"
zlib_includes_result="$ZLIB_INCLUDES"

if test x"$zlib_libraries_result" = x""; then
  zlib_libraries_result="in default path"
fi
if test x"$zlib_includes_result" = x""; then
  zlib_includes_result="in default path"
fi

if test "$zlib_libraries_result" = "no"; then
  zlib_libraries_result="(none)"
fi
if test "$zlib_includes_result" = "no"; then
  zlib_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $zlib_libraries_result, headers $zlib_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$ZLIB_INCLUDES" != "no" && test "$ZLIB_LIBS" != "no"; then
  AC_DEFINE(HAVE_ZLIB,1,[Define if you have zlib libraries and header files.])
  $1
else
  ZLIB_INCLUDES=""
  ZLIB_LIBS=""
  $2
fi

])dnl
