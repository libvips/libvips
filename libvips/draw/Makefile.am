noinst_LTLIBRARIES = libdraw.la

libdraw_la_SOURCES = \
	line.h \
	line.c \
	circle.c \
	draw.c \
	flood.c \
	paintmask.c \
	im_draw_image.c \
	im_draw_line.c \
	im_draw_point.c \
	im_draw_rect.c \
	im_draw_smudge.c \
	inplace_dispatch.c \
	old_draw.c \
	old_draw.h \
	pdraw.h 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
