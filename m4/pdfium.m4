dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_PDFIUM[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ---------------------------------------------------
dnl
dnl Find pdfium libraries and headers 
dnl
dnl Put -I stuff in PDFIUM_INCLUDES
dnl Put PDFium objects in PDFIUM_LIBS (add this to the link line untouched!)
dnl Define HAVE_PDFIUM if found
dnl
AC_DEFUN([FIND_PDFIUM], [
AC_REQUIRE([AC_PATH_XTRA])

ZLIB_INCLUDES=""
ZLIB_LIBS=""

AC_ARG_WITH(pdfium, 
  AS_HELP_STRING([--without-pdfium], [build without pdfium (default: test)]))
# Treat --without-pdfium like --without-pdfium-includes 
# --without-pdfium-libraries
if test "$with_pdfium" = "no"; then
  PDFIUM_INCLUDES=no
  PDFIUM_LIBS=no
fi

AC_ARG_WITH(pdfium-includes,
  AS_HELP_STRING([--with-pdfium-includes=DIR], [pdfium includes are in DIR]),
  PDFIUM_INCLUDES="-I$withval")
AC_ARG_WITH(pdfium-libraries,
  AS_HELP_STRING([--with-pdfium-libraries=DIR], [pdfium libraries are in DIR]),
  PDFIUM_LIBS="$withval")

AC_MSG_CHECKING(for PDFIUM)

# Look for fpdfview.h ... this is a documented header, so it should be a good
# target 
#
# it won't be in the standard search path, but try $PREFIX
if test "$PDFIUM_INCLUDES" = ""; then
  pdfium_save_CPPFLAGS="$CPPFLAGS"

  CPPFLAGS="-I${prefix}/include $CPPFLAGS"

  AC_TRY_COMPILE([#include <fpdfview.h>],[int a;],[
     PDFIUM_INCLUDES="-I${prefix}/include"
    ], [
     PDFIUM_INCLUDES="no"
    ]
  )

  CPPFLAGS="$pdfium_save_CPPFLAGS"
fi

# Now for the libraries ... if there's nothing set, try $PREFIX/lib 
if test "$PDFIUM_LIBS" = ""; then
  pdfium_save_LIBS="$LIBS"
  pdfium_save_CPPFLAGS="$CPPFLAGS"

  LIBS="-L$prefix/lib -lpdfium -lc++ -licuuc $LIBS"
  CPPFLAGS="$PDFIUM_INCLUDES $CPPFLAGS"

  AC_TRY_LINK([#include <fpdfview.h>],
     [FPDF_DOCUMENT doc; doc = FPDF_LoadDocument("", "")],
    [PDFIUM_LIBS="${prefix}/lib"],
    [PDFIUM_LIBS=no])

  LIBS="$pdfium_save_LIBS"
  CPPFLAGS="$pdfium_save_CPPFLAGS"
fi

# Print a helpful message
pdfium_libraries_result="$PDFIUM_LIBS"
pdfium_includes_result="$PDFIUM_INCLUDES"

if test x"$pdfium_libraries_result" = x""; then
  pdfium_libraries_result="in default path"
fi
if test x"$pdfium_includes_result" = x""; then
  pdfium_includes_result="in default path"
fi

if test "$pdfium_libraries_result" = "no"; then
  pdfium_libraries_result="(none)"
fi
if test "$pdfium_includes_result" = "no"; then
  pdfium_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $pdfium_libraries_result, headers $pdfium_includes_result])

if test x"$PDFIUM_LIBS" != x"no"; then
  dir="$PDFIUM_LIBS"
  PDFIUM_LIBS="-L$dir -lpdfium -lc++ -licuuc"
fi

AC_SUBST(PDFIUM_LIBS)
AC_SUBST(PDFIUM_INCLUDES)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$PDFIUM_INCLUDES" != "no" && test "$PDFIUM_LIBS" != "no"; then
  AC_DEFINE(HAVE_PDFIUM,1,
    [Define if you have pdfium libraries and header files.])
  $1
else
  PDFIUM_INCLUDES=""
  PDFIUM_LIBS=""
  $2
fi

])dnl
