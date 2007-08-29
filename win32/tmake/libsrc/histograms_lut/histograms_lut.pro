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
	hist_dispatch.c \
	im_gammacorrect.c \
	im_heq.c \
	im_hist.c \
	im_histeq.c \
	im_histgr.c \
	im_histnD.c \
	im_histplot.c \
	im_histspec.c \
	im_hsp.c \
	im_identity.c \
	im_invertlut.c \
	im_lhisteq.c \
	im_maplut.c \
	im_stdif.c \
	tone.c
TARGET		= histograms_lut
