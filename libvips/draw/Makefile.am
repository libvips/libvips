noinst_LTLIBRARIES = libdraw.la

libdraw_la_SOURCES = \
	draw.c \
	pdraw.h \
	draw_circle.c \
	draw_flood.c \
	draw_mask.c \
	draw_image.c \
	draw_rect.c \
	draw_line.h \
	draw_line.c \
	draw_line_mask.c \
	draw_line_user.c \
	im_draw_smudge.c \
	inplace_dispatch.c \
	old_draw.c \
	old_draw.h

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
