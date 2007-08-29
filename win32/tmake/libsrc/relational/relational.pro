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
	im_ifthenelse.c \
	im_blend.c \
	relational.c \
	relational_dispatch.c
TARGET		= relational

