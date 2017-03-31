## Process this file with automake to produce Makefile.in

# We require automake 1.6 at least.
AUTOMAKE_OPTIONS = 1.6

# This is a blank Makefile.am for using gtk-doc.
# Copy this to your project's API docs directory and modify the variables to
# suit your project. See the GTK+ Makefiles in gtk+/docs/reference for examples
# of using the various options.

# The name of the module, e.g. 'glib'.
DOC_MODULE=libvips

# Uncomment for versioned docs and specify the version of the module, e.g. '2'.
#DOC_MODULE_VERSION=2


# The top-level XML file (SGML in the past). You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.xml

# Directories containing the source code.
# gtk-doc will search all .c and .h files beneath these paths
# for inline comments documenting functions and macros.
# e.g. DOC_SOURCE_DIR=$(top_srcdir)/gtk $(top_srcdir)/gdk
DOC_SOURCE_DIR=$(top_srcdir)/libvips

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED"
SCAN_OPTIONS=--rebuild-types

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--xml-mode --output-format=xml
MKDB_OPTIONS=--xml-mode --output-format=xml

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# Extra options to supply to gtkdoc-mkhtml
MKHTML_OPTIONS=

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/gtk/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/gtk/*.c
HFILE_GLOB=$(top_srcdir)/libvips/include/vips/*.h
CFILE_GLOB=$(top_srcdir)/libvips/*/*.c

# Extra header to include when scanning, which are not under DOC_SOURCE_DIR
# e.g. EXTRA_HFILES=$(top_srcdir}/contrib/extra.h
EXTRA_HFILES=

# Header files or dirs to ignore when scanning. Use base file/dir names
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h private_code

IGNORE_VIPS_INCLUDE = \
	almostdeprecated.h \
	cimg_funcs.h \
	deprecated.h \
	vips7compat.h \
	dispatch.h \
	enumtypes.h \
	internal.h \
	thread.h \
	intl.h \
	format.h \
	mask.h \
	private.h \
	video.h 

# ignore all .h files in libvips/*, these are internal
IGNORE_VIPS_C = \
	binary.h \
	hough.h \
	nary.h \
	parithmetic.h \
	statistic.h \
	unaryconst.h \
	unary.h \
	CImg.h \
	pcolour.h \
	bandary.h \
	pconversion.h \
	correlation.h \
	pconvolution.h \
	pcreate.h \
	pmask.h \
	point.h \
	drawink.h \
	pdraw.h \
	analyze2vips.h \
	csv.h \
	dbh.h \
	fits.h \
	jpeg.h \
	magick.h \
	matlab.h \
	openexr2vips.h \
	openslide2vips.h \
	ppm.h \
	radiance.h \
	tiff.h \
	vipsjpeg.h \
	vipspng.h \
	webp.h \
	pfreqfilt.h \
	hist_unary.h \
	phistogram.h \
	base64.h \
	sink.h \
	vipsmarshal.h \
	pmorphology.h \
	global_balance.h \
	pmosaicing.h \
	presample.h \
	templates.h

IGNORE_HFILES = $(IGNORE_VIPS_INCLUDE) $(IGNORE_VIPS_C)

# Images to copy into HTML directory.
# e.g. HTML_IMAGES=$(top_srcdir)/gtk/stock-icons/stock_about_24.png
HTML_IMAGES = \
	$(top_srcdir)/doc/images/interconvert.png \
	$(top_srcdir)/doc/images/Combine.png \
	$(top_srcdir)/doc/images/Memtrace.png \
	$(top_srcdir)/doc/images/Sequence.png \
	$(top_srcdir)/doc/images/Sink.png \
	$(top_srcdir)/doc/images/Vips-smp.png

# we have some files in markdown ... convert to docbook for gtk-doc
# pandoc makes sect1 headers, we want refsect3 for gtk-doc
.md.xml:
	pandoc -s -S --template="$(realpath pandoc-docbook-template.docbook)" --wrap=none -V title="$<" -f markdown -t docbook -o $@ $<
	sed -e s/sect1/refsect3/g < $@ > x && mv x $@

# Our markdown source files
markdown_content_files = \
	How-it-works.md

# converted to xml in this dir by pandoc
markdown_content_files_docbook = $(markdown_content_files:.md=.xml)

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
# e.g. content_files=running.sgml building.sgml changes-2.0.sgml
content_files = \
	using-command-line.xml \
	using-C.xml \
	using-threads.xml \
	using-python.xml \
	using-cpp.xml \
	extending.xml \
	function-list.xml \
	file-format.xml \
	${markdown_content_files_docbook} \
	binding.xml

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
# These files must be listed here *and* in content_files
# e.g. expand_content_files=running.sgml
expand_content_files = \
	using-command-line.xml \
	using-C.xml \
	using-threads.xml \
	using-python.xml \
	using-cpp.xml \
	extending.xml \
	function-list.xml \
	file-format.xml \
	${markdown_content_files_docbook} \
	binding.xml

# CFLAGS and LDFLAGS for compiling gtkdoc-scangobj with your library.
# Only needed if you are using gtkdoc-scangobj to dynamically query widget
# signals and properties.
# e.g. GTKDOC_CFLAGS=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
GTKDOC_CFLAGS = @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
GTKDOC_LIBS = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@

# This includes the standard gtk-doc make rules, copied by gtkdocize.
include gtk-doc.make

# Other files to distribute
# e.g. EXTRA_DIST += version.xml.in
EXTRA_DIST += \
        ${markdown_content_files} \
	images \
	gen-function-list.py

# Files not to distribute
# for --rebuild-types in $(SCAN_OPTIONS), e.g. $(DOC_MODULE).types
# for --rebuild-sections in $(SCAN_OPTIONS) e.g. $(DOC_MODULE)-sections.txt
DISTCLEANFILES = libvips.types 

# Comment this out if you want 'make check' to test you doc status
# and run some sanity checks
if ENABLE_GTK_DOC
TESTS_ENVIRONMENT = \
  DOC_MODULE=$(DOC_MODULE) DOC_MAIN_SGML_FILE=$(DOC_MAIN_SGML_FILE) \
  SRCDIR=$(abs_srcdir) BUILDDIR=$(abs_builddir)
#TESTS = $(GTKDOC_CHECK)
endif

-include $(top_srcdir)/git.mk
