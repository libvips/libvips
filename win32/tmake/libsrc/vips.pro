TEMPLATE    	= app
DIR_LIB		= ../lib
CONFIG      	= release dll
win32:CONFIG  	+= windows
TMAKEFLAGS	= -nologo
INCLUDEPATH	= .. ../include
HEADERS		= ../config.h
SOURCES		= dummy.c
DESTDIR		= ../Release
unix:LIBS	+= \
	$$DESTDIR/*.a 
win32:LIBS	+= \
	$$DESTDIR/*.lib \
	$$DIR_LIB/libjpeg.lib \
	$$DIR_LIB/libtiff.lib \
	$$DIR_LIB/libpng.lib \
	$$DIR_LIB/libz.lib
DEF_FILE	= vips.def
TARGET		= vips
VERSION		= 7.8.10
CLEAN 		= $$DESTDIR/vips.exp $$DESTDIR/vips.lib
