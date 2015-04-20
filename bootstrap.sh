#!/bin/sh

# set -x

# a bunch of cleaning up ... make certain everything will be regenerated
rm -f Makefile Makefile.in aclocal.m4 
rm -rf autom4te.cache
rm -f m4/*
rm -f config.* configure depcomp
rm -f install-sh intltool-* libtool ltmain.sh missing mkinstalldirs
rm -f stamp-* vipsCC-7.19.pc vips-7.19.spec vips-7.19.pc
rm -f swig/vipsCC/*.cxx
rm -f swig/vipsCC/VImage.h
rm -f swig/vipsCC/VImage.py python/vipsCC/VError.py python/vipsCC/VMask.py python/vipsCC/Display.py
rm -f benchmark/temp*
( mkdir poop ; \
	mv doc/libvips-docs.xml.in poop ; \
	mv doc/Makefile.am poop ; \
	mv doc/images poop ; \
	mv doc/*.xml poop ; \
	mv doc/*.py poop ; \
	rm -rf doc/* ; \
	mv poop/* doc ; \
	rmdir poop \
)

# glib-gettextize asks us to copy these files to m4 if they aren't there
# I don't have $ACDIR/isc-posix.m4, how mysterious
ACDIR=`aclocal --print-ac-dir`

# OS X with brew sets ACDIR to
# /usr/local/Cellar/automake/1.13.1/share/aclocal, the staging area, which is
# totally wrong argh
if [ ! -d $ACDIR ]; then
	ACDIR=/usr/local/share/aclocal
fi

mkdir -p m4
cp $ACDIR/codeset.m4 m4
cp $ACDIR/gettext.m4 m4
cp $ACDIR/glibc21.m4 m4
cp $ACDIR/iconv.m4 m4
cp $ACDIR/lcmessage.m4 m4
cp $ACDIR/progtest.m4 m4
cp $ACDIR/introspection.m4 m4

gtkdocize --copy --docdir doc --flavour no-tmpl || exit 1

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
# gettextize produces quite a bit of benign and misleading text output, hide
# it ... hopefully any errors will go to stderr and not be hidden
glib-gettextize --force --copy > /dev/null
test -r aclocal.m4 && chmod u+w aclocal.m4
# intltoolize --copy --force --automake
aclocal 
autoconf
autoheader
$LIBTOOLIZE --copy --force --automake
automake --add-missing --copy

swig -version > /dev/null
if [ $? -ne 0 ]; then
  echo you need swig to build from source control
fi
