#!/bin/sh

# set -x

# a bunch of cleaning up ... make certain everything will be regenerated
rm -f Makefile Makefile.in aclocal.m4 
rm -rf autom4te.cache
rm -f config.* configure depcomp
rm -f install-sh intltool-* libtool ltmain.sh missing mkinstalldirs
rm -f stamp-* vipsCC-7.19.pc vips-7.19.spec vips-7.19.pc
rm -f python/vipsCC/*.cxx
rm -f python/vipsCC/VImage.h
rm -f python/vipsCC/VImage.py python/vipsCC/VError.py python/vipsCC/VMask.py python/vipsCC/Display.py
rm -f benchmark/temp*

# some systems need libtoolize, some glibtoolize ... how annoying
echo testing for glibtoolize ...
if glibtoolize --version >/dev/null 2>&1; then 
  LIBTOOLIZE=glibtoolize
  echo using glibtoolize 
else 
  LIBTOOLIZE=libtoolize
  echo using libtoolize 
fi

test -r aclocal.m4 || touch aclocal.m4
glib-gettextize --force --copy
test -r aclocal.m4 && chmod u+w aclocal.m4
# intltoolize --copy --force --automake
aclocal 
autoconf
autoheader
$LIBTOOLIZE --copy --force --automake
automake --add-missing --copy

