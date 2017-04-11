dnl Look for expat, set EXPAT_CFLAGS, EXPAT_LIBS
dnl Use --with-expat=PREFIX to set a specific prefix
dnl
dnl This is modified from the usual expat.m4:
dnl - default to with_expat=yes
dnl - don't set a conditional

AC_DEFUN([AM_WITH_EXPAT],
[ AC_ARG_WITH(expat,
	      [  --with-expat=PREFIX     Use system Expat library],
	      , with_expat=yes)

  EXPAT_CFLAGS=
  EXPAT_LIBS=
  if test $with_expat != no; then
	if test $with_expat != yes; then
		EXPAT_CFLAGS="-I$with_expat/include"
		EXPAT_LIBS="-L$with_expat/lib"
	fi
	AC_CHECK_LIB(expat, XML_ParserCreate,
		     [ EXPAT_LIBS="$EXPAT_LIBS -lexpat"
		       expat_found=yes ],
		     [ expat_found=no ],
		     "$EXPAT_LIBS")
	if test $expat_found = no; then
		AC_MSG_ERROR([Could not find the Expat library])
	fi
	expat_save_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $EXPAT_CFLAGS"
	AC_CHECK_HEADERS(expat.h, , expat_found=no)
	if test $expat_found = no; then
		AC_MSG_ERROR([Could not find expat.h])
	fi
	CFLAGS="$expat_save_CFLAGS"
  fi

  AC_SUBST(EXPAT_CFLAGS)
  AC_SUBST(EXPAT_LIBS)
])
