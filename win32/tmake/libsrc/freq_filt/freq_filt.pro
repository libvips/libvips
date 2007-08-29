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
	fft_sp.c \
	fmask4th.c \
	fmaskcir.c \
	freq_dispatch.c \
	im_disp_ps.c \
	im_fractsurf.c \
	im_freq_mask.c \
	im_freqflt.c \
	im_fwfft.c \
	im_invfft.c \
	im_invfftr.c \
	im_rotquad.c
TARGET		= freq_filt

