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
	colour.c \
	colour_dispatch.c \
	derived.c \
	im_icc_transform.c \
	im_LCh2Lab.c \
	im_LCh2UCS.c \
	im_Lab2LCh.c \
	im_Lab2LabQ.c \
	im_Lab2LabS.c \
	im_Lab2XYZ.c \
	im_LabQ2Lab.c \
	im_LabQ2LabS.c \
	im_LabQ2disp.c \
	im_LabS2LabQ.c \
	im_LabS2Lab.c \
	im_lab_morph.c \
	im_UCS2LCh.c \
	im_XYZ2Lab.c \
	im_XYZ2Yxy.c \
	im_Yxy2XYZ.c \
	im_XYZ2disp.c \
	im_dE00_fromLab.c \
	im_dECMC_fromLab.c \
	im_dE_fromLab.c \
	im_disp2XYZ.c
TARGET		= colour
