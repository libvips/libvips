#!/bin/sh

# set -x

# a bunch of cleaning up ... make certain everything will be regenerated
rm -f Makefile Makefile.in aclocal.m4 
rm -rf autom4te.cache
# m4/ contains only stuff from the build system ... the m4 files we have
# written and maintain are in m4-safe
rm -f m4/* 
cp m4-safe/* m4/
rm -f config.* configure depcomp
rm -f install-sh intltool-* libtool ltmain.sh missing mkinstalldirs
rm -f stamp-* vipsCC-7.19.pc vips-7.19.spec vips-7.19.pc
rm -f swig/vipsCC/*.cxx
rm -f swig/vipsCC/VImage.h
rm -f swig/vipsCC/VImage.py python/vipsCC/VError.py python/vipsCC/VMask.py python/vipsCC/Display.py
rm -f benchmark/temp*
find doc -depth \( \
      -path doc/libvips-docs.xml.in \
   -o -path doc/Makefile.am \
   -o -path 'doc/images/*' \
   -o -name '*.xml' ! -name libvips-docs.xml ! -path 'doc/xml/*' \
   -o -name '*.py' \
\) -prune -or \( \
      -type f \
   -o -type d -empty \
\) -delete

ACDIR=`aclocal --print-ac-dir`
# OS X with brew has a dirlist in ACDIR that points to several directories
# dirlist supports wildcards, but that would require eval ... which is evil
if [ -e $ACDIR/dirlist ]; then
  ACDIR=`cat $ACDIR/dirlist`
fi

# glib-gettextize asks us to copy these files to m4 if they aren't there:
files="codeset gettext glibc21 iconv isc-posix lcmessage progtest introspection"
for dir in $ACDIR; do
  test -d $dir && for file in $files; do
    test -e $dir/$file.m4 && cp $dir/$file.m4 m4
  done
done

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
aclocal -I m4
autoconf
autoheader
$LIBTOOLIZE --copy --force --automake
automake --add-missing --copy

swig -version > /dev/null
if [ $? -ne 0 ]; then
  echo you need swig to build from source control
fi
