noinst_LTLIBRARIES = libdraw.la

libdraw_la_SOURCES = \
	draw.c \
	pdraw.h \
	flood.c \
	im_draw_circle.c \
	im_draw_line.c \
	im_draw_image.c \
	im_draw_rect.c \
	im_draw_mask.c \
	im_draw_point.c \
	im_draw_smudge.c \
	inplace_dispatch.c

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
