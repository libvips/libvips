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
		arith_dispatch.c \
	    	im_abs.c \
		im_add.c \
		im_avg.c \
		im_cmulnorm.c \
		im_costra.c \
		im_deviate.c \
		im_divide.c \
		im_ceil.c \
		im_floor.c \
		im_expntra.c \
		im_fav4.c \
		im_gadd.c \
		im_gaddim.c \
		im_gfadd.c \
		im_invert.c \
		im_lintra.c \
		im_litecor.c \
		im_log10tra.c \
		im_logtra.c \
		im_max.c \
		im_maxpos.c \
		im_measure.c \
		im_min.c \
		im_minpos.c \
		im_multiply.c \
		im_powtra.c \
		im_remainder.c \
		im_sign.c \
		im_sintra.c \
		im_stats.c \
		im_subtract.c \
		im_tantra.c 
TARGET		= arithmetic
