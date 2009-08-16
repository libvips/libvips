noinst_LTLIBRARIES = libformat.la

libformat_la_SOURCES = \
	dbh.h \
	format.c \
	format_dispatch.c \
	im_analyze2vips.c \
	im_csv2vips.c \
	im_exr2vips.c \
	im_jpeg2vips.c \
	im_magick2vips.c \
	im_png2vips.c \
	im_ppm2vips.c \
	im_raw2vips.c \
	im_tiff2vips.c \
	im_tile_cache.c \
	im_vips2csv.c \
	im_vips2jpeg.c \
	im_vips2png.c \
	im_vips2ppm.c \
	im_vips2tiff.c \
	im_vips2raw.c \
	matlab.c \
	radiance.c 

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
