TEMPLATE    	= lib
DIR_LIB		= ../../lib
CONFIG 		= release staticlib 
win32:CONFIG 	= windows
TMAKEFLAGS	= -nologo
DEFINES		= HAVE_CONFIG_H
INCLUDEPATH	= ../.. ../../include
HEADERS		= ../../config.h
win32:LIBS	= \
	$$DIR_LIB/libjpeg.lib \
	$$DIR_LIB/libtiff.lib \
	$$DIR_LIB/libpng.lib \
	$$DIR_LIB/libz.lib
DESTDIR		= ../../Release
VERSION		= 7.8.10

SOURCES		= \
	callback.c \
	debug.c \
	dispatch_types.c \
	error.c \
	error_exit.c \
	im_append_Hist.c \
	im_binfile.c \
	im_close.c \
	im_cp_Hist.c \
	im_cp_desc.c \
	im_crwrhd.c \
	im_debugim.c \
	im_demand_hint.c \
	im_desc_hd.c \
	im_generate.c \
	im_header.c \
	im_histlin.c \
	im_image.c \
	im_init.c \
	im_initdesc.c \
	im_inithd.c \
	im_iocheck.c \
	im_iterate.c \
	im_makerw.c \
	im_mapfile.c \
	im_openin.c \
	im_open.c \
	im_openout.c \
	im_partial.c \
	im_piocheck.c \
	im_prepare.c \
	im_printdesc.c \
	im_printhd.c \
	im_printlines.c \
	im_readhist.c \
	im_setbox.c \
	im_setbuf.c \
	im_setupout.c \
	im_unmapfile.c \
	im_updatehist.c \
	im_guess_prefix.c \
	im_wrapmany.c \
	im_wrapone.c \
	im_writeline.c \
	list.c \
	memory.c \
	package.c \
	predicate.c \
	region.c \
	rect.c \
	thread.c \
	threadgroup.c \
	time.c
TARGET		= iofuncs

