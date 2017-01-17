dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_PNG[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find PNG libraries and headers
dnl
dnl Put compile stuff in PNG_INCLUDES
dnl Put link stuff in PNG_LIBS
dnl Define HAVE_PNG if found.
dnl
AC_DEFUN([FIND_PNG], [
AC_REQUIRE([AC_PATH_XTRA])

PNG_INCLUDES=""
PNG_LIBS=""

AC_ARG_WITH(png, 
  AS_HELP_STRING([--without-png], [build without libpng (default: test)]))
# Treat --without-png like --without-png-includes --without-png-libraries.
if test "$with_png" = "no"; then
  PNG_INCLUDES=no
  PNG_LIBS=no
fi

AC_ARG_WITH(png-includes,
  AS_HELP_STRING([--with-png-includes=DIR], [libpng includes are in DIR]),
  PNG_INCLUDES="-I$withval")
AC_ARG_WITH(png-libraries,
  AS_HELP_STRING([--with-png-libraries=DIR], [libpng libraries are in DIR]),
  PNG_LIBS="-L$withval -lpng")

AC_MSG_CHECKING(for libpng)

# Look for png.h 
if test "$PNG_INCLUDES" = ""; then
  # Check the standard search path
  AC_TRY_COMPILE([#include <png.h>],[int a;],[
    PNG_INCLUDES=""
  ], [
    # png.h is not in the standard search path, try
    # $prefix
    png_save_INCLUDES="$INCLUDES"

    INCLUDES="-I${prefix}/include $INCLUDES"

    AC_TRY_COMPILE([#include <png.h>],[int a;],[
      PNG_INCLUDES="-I${prefix}/include"
    ], [
      PNG_INCLUDES="no"
    ])

    INCLUDES=$png_save_INCLUDES
  ])
fi

# Now for the libraries
if test "$PNG_LIBS" = ""; then
  png_save_LIBS="$LIBS"
  png_save_INCLUDES="$INCLUDES"

  LIBS="-lpng $LIBS"
  INCLUDES="$PNG_INCLUDES $INCLUDES"

  # Try the standard search path first
  AC_TRY_LINK([#include <png.h>],[png_access_version_number()], [
    PNG_LIBS="-lpng"
  ], [
    # libpng is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <png.h>],[png_access_version_number()], [
      PNG_LIBS="-L${prefix}/lib -lpng"
    ], [
      PNG_LIBS=no
    ])
  ])

  LIBS="$png_save_LIBS"
  INCLUDES="$png_save_INCLUDES"
fi

AC_SUBST(PNG_LIBS)
AC_SUBST(PNG_INCLUDES)

# Print a helpful message
png_libraries_result="$PNG_LIBS"
png_includes_result="$PNG_INCLUDES"

if test x"$png_libraries_result" = x""; then
  png_libraries_result="in default path"
fi
if test x"$png_includes_result" = x""; then
  png_includes_result="in default path"
fi

if test "$png_libraries_result" = "no"; then
  png_libraries_result="(none)"
fi
if test "$png_includes_result" = "no"; then
  png_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $png_libraries_result, headers $png_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$PNG_INCLUDES" != "no" && test "$PNG_LIBS" != "no"; then
  AC_DEFINE(HAVE_PNG,1,[Define if you have png libraries and header files.])
  $1
else
  PNG_INCLUDES=""
  PNG_LIBS=""
  $2
fi

])dnl
