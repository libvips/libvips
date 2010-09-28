noinst_LTLIBRARIES = libinplace.la

libinplace_la_SOURCES = \
	draw.c \
	draw.h \
	im_draw_circle.c \
	im_draw_line.c \
	im_draw_image.c \
	im_draw_rect.c \
	im_draw_mask.c \
	flood.c \
	inplace_dispatch.c \
	plot_point.c \
	smudge_area.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
