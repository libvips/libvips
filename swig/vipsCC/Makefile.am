# Let make substitute the value of PYTHON_INCLUDES rather than auto*
# this makes it easier to support multiple python installs
INCLUDES = \
	-I${top_srcdir}/libvips/include \
	-I${top_srcdir}/libvipsCC/include \
	@VIPS_CFLAGS@ \
	@VIPS_INCLUDES@ \
	$(PYTHON_INCLUDES)

# we install to a directory inside the python area, since we are a module
vipsccdir = $(pyexecdir)/vipsCC

vipscc_PYTHON = VImage.py VDisplay.py VError.py VMask.py __init__.py

# I tried making a suffix rule for this (and defining SUFFIXES) but I couldn't
# get it to work, how annoying 
# FIXME at some point
#
# need an expanded VImage.h ... SWIG's preprocessor b0rks on includes inside
# class definitions
vimagemodule.cxx: VImage.i
	cpp -DSWIG -E $(top_srcdir)/libvipsCC/include/vips/VImage.h > VImage.h
	swig -python -c++ -interface $(@:.cxx=) -I$(top_srcdir)/libvipsCC/include -o $@ $<

vdisplaymodule.cxx: VDisplay.i
	swig -python -c++ -interface $(@:.cxx=) -I$(top_srcdir)/libvipsCC/include -o $@ $<
verrormodule.cxx: VError.i
	swig -python -c++ -interface $(@:.cxx=) -I$(top_srcdir)/libvipsCC/include -o $@ $<
vmaskmodule.cxx: VMask.i
	swig -python -c++ -interface $(@:.cxx=) -I$(top_srcdir)/libvipsCC/include -o $@ $<

vipscc_LTLIBRARIES = vimagemodule.la vdisplaymodule.la verrormodule.la vmaskmodule.la

# maybe there's a clever way to avoid repeating the link stuff 4 times
# vimagemodule uses the C API as well, so it needs libvips too
vimagemodule_la_LDFLAGS = -module -avoid-version 
vimagemodule_la_LIBADD = ../../libvipsCC/libvipsCC.la ../../libvips/libvips.la $(VIPS_LIBS)
nodist_vimagemodule_la_SOURCES = vimagemodule.cxx 

vdisplaymodule_la_LDFLAGS = -module -avoid-version 
vdisplaymodule_la_LIBADD = ../../libvipsCC/libvipsCC.la $(VIPS_LIBS)
nodist_vdisplaymodule_la_SOURCES = vdisplaymodule.cxx 

verrormodule_la_LDFLAGS = -module -avoid-version 
verrormodule_la_LIBADD = ../../libvipsCC/libvipsCC.la $(VIPS_LIBS)
nodist_verrormodule_la_SOURCES = verrormodule.cxx 

vmaskmodule_la_LDFLAGS = -module -avoid-version 
vmaskmodule_la_LIBADD = ../../libvipsCC/libvipsCC.la $(VIPS_LIBS)
nodist_vmaskmodule_la_SOURCES = vmaskmodule.cxx 

CLEANFILES = VImage.h 

EXTRA_DIST = \
	VImage.i VDisplay.i VError.i VMask.i __init__.py \
	vimagemodule.cxx \
	verrormodule.cxx vdisplaymodule.cxx vmaskmodule.cxx \
	VImage.py VDisplay.py VError.py VMask.py
