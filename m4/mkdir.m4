dnl @synopsis AC_FUNC_MKDIR
dnl
dnl Check whether mkdir() is mkdir or _mkdir, and whether it takes one
dnl or two arguments.
dnl
dnl This macro can define HAVE_MKDIR, HAVE__MKDIR, and
dnl MKDIR_TAKES_ONE_ARG, which are expected to be used as follows:
dnl
dnl   #if HAVE_MKDIR
dnl   #  if MKDIR_TAKES_ONE_ARG
dnl        /* MinGW32 */
dnl   #    define mkdir(a, b) mkdir(a)
dnl   #  endif
dnl   #else
dnl   #  if HAVE__MKDIR
dnl        /* plain Windows 32 */
dnl   #    define mkdir(a, b) _mkdir(a)
dnl   #  else
dnl   #    error "Don't know how to create a directory on this system."
dnl   #  endif
dnl   #endif
dnl
dnl @category C
dnl @author Alexandre Duret-Lutz <adl@gnu.org>
dnl @version 2003-12-28
dnl @license GPLWithACException

AC_DEFUN([AC_FUNC_MKDIR],
[AC_CHECK_FUNCS([mkdir _mkdir])
AC_CACHE_CHECK([whether mkdir takes one argument],
               [ac_cv_mkdir_takes_one_arg],
[AC_TRY_COMPILE([
#include <sys/stat.h>
#if HAVE_UNISTD_H
#  include <unistd.h>
#endif
], [mkdir (".");],
[ac_cv_mkdir_takes_one_arg=yes], [ac_cv_mkdir_takes_one_arg=no])])
if test x"$ac_cv_mkdir_takes_one_arg" = xyes; then
  AC_DEFINE([MKDIR_TAKES_ONE_ARG], 1,
            [Define if mkdir takes only one argument.])
fi
])

dnl Note:
dnl =====
dnl I have not implemented the following suggestion because I don't have
dnl access to such a broken environment to test the macro.  So I'm just
dnl appending the comments here in case you have, and want to fix
dnl AC_FUNC_MKDIR that way.
dnl
dnl |Thomas E. Dickey (dickey@herndon4.his.com) said:
dnl |  it doesn't cover the problem areas (compilers that mistreat mkdir
dnl |  may prototype it in dir.h and dirent.h, for instance).
dnl |
dnl |Alexandre:
dnl |  Would it be sufficient to check for these headers and #include
dnl |  them in the AC_TRY_COMPILE block?  (and is AC_HEADER_DIRENT
dnl |  suitable for this?)
dnl |
dnl |Thomas:
dnl |  I think that might be a good starting point (with the set of recommended
dnl |  ifdef's and includes for AC_HEADER_DIRENT, of course).
