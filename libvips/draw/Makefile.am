noinst_LTLIBRARIES = libdraw.la

libdraw_la_SOURCES = \
	draw.c \
	pdraw.h \
	drawink.c \
	drawink.h \
	draw_circle.c \
	draw_flood.c \
	draw_mask.c \
	draw_image.c \
	draw_add.c \
	draw_rect.c \
	draw_line.h \
	draw_line.c \
	draw_line_mask.c \
	draw_line_user.c \
	draw_smudge.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
