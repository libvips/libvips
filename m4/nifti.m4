dnl From FIND_MOTIF and ACX_PTHREAD, without much understanding
dnl
dnl FIND_NIFTI[ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]]
dnl ------------------------------------------------
dnl
dnl Find NIFTI libraries and headers
dnl
dnl Put compile stuff in NIFTI_INCLUDES
dnl Put link stuff in NIFTI_LIBS
dnl Define HAVE_NIFTI if found
dnl
AC_DEFUN([FIND_NIFTI], [
AC_REQUIRE([AC_PATH_XTRA])

NIFTI_INCLUDES=""
NIFTI_LIBS=""

AC_ARG_WITH(nifti, 
  AS_HELP_STRING([--without-nifti], [build without nifti (default: test)]))
# Treat --without-nifti like --without-nifti-includes --without-nifti-libraries.
if test "$with_nifti" = "no"; then
  NIFTI_INCLUDES=no
  NIFTI_LIBS=no
fi

AC_ARG_WITH(nifti-includes,
  AS_HELP_STRING([--with-nifti-includes=DIR], [libniftiio includes are in DIR]),
  NIFTI_INCLUDES="-I$withval"
)
AC_ARG_WITH(nifti-libraries,
  AS_HELP_STRING([--with-nifti-libraries=DIR], 
    [libniftiio libraries are in DIR]),
  NIFTI_LIBS="-L$withval -lniftiio -lznz"
)

AC_MSG_CHECKING(for NIFTI)

# Look for nifti1_io.h ... usually in /usr/include/nifti
if test "$NIFTI_INCLUDES" = ""; then
  nifti_save_CFLAGS="$CFLAGS"

  # annoyingly, the header must be unqualified, so we have to add to the
  # search path
  CFLAGS="-I/usr/include/nifti $nifti_save_CFLAGS"

  AC_TRY_COMPILE([#include <nifti1_io.h>],[int a;],[
    NIFTI_INCLUDES="-I/usr/include/nifti"
  ], [
    # not in the standard search path, try $prefix
    CFLAGS="-I${prefix}/include/nifti $nifti_save_CFLAGS"

    AC_TRY_COMPILE([#include <nifti1_io.h>],[int a;],[
      NIFTI_INCLUDES="-I${prefix}/include/nifti"
    ], [
      NIFTI_INCLUDES="no"
    ])
  ])

  CFLAGS="$nifti_save_CFLAGS"
fi

# Now for the libraries
if test "$NIFTI_LIBS" = ""; then
  nifti_save_LIBS="$LIBS"
  nifti_save_CFLAGS="$CFLAGS"

  LIBS="-lniftiio -lznz -lm $nifti_save_LIBS"
  CFLAGS="$NIFTI_INCLUDES $CFLAGS"

  # Try the standard search path first
  AC_TRY_LINK([#include <nifti1_io.h>],[is_nifti_file("")], [
    NIFTI_LIBS="-lniftiio -lznz"
  ], [
    # libniftiio is not in the standard search path, try $prefix

    LIBS="-L${prefix}/lib $LIBS"

    AC_TRY_LINK([#include <nifti1_io.h>],[is_nifti_file("")], [
      NIFTI_LIBS="-L${prefix}/lib -lniftiio -lznz"
    ], [
      NIFTI_LIBS=no
    ])
  ])

  LIBS="$nifti_save_LIBS"
  CFLAGS="$nifti_save_CFLAGS"
fi

AC_SUBST(NIFTI_LIBS)
AC_SUBST(NIFTI_INCLUDES)

# Print a helpful message
nifti_libraries_result="$NIFTI_LIBS"
nifti_includes_result="$NIFTI_INCLUDES"

if test x"$nifti_libraries_result" = x""; then
  nifti_libraries_result="in default path"
fi
if test x"$nifti_includes_result" = x""; then
  nifti_includes_result="in default path"
fi

if test "$nifti_libraries_result" = "no"; then
  nifti_libraries_result="(none)"
fi
if test "$nifti_includes_result" = "no"; then
  nifti_includes_result="(none)"
fi

AC_MSG_RESULT([libraries $nifti_libraries_result, headers $nifti_includes_result])

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test "$NIFTI_INCLUDES" != "no" && test "$NIFTI_LIBS" != "no"; then
  AC_DEFINE(HAVE_NIFTI,1,[Define if you have nifti libraries and header files.])
  $1
else
  NIFTI_INCLUDES=""
  NIFTI_LIBS=""
  $2
fi

])dnl
