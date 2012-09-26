noinst_LTLIBRARIES = libcolour.la

libcolour_la_SOURCES = \
	colour.c \
	colour_funcs.c \
	colour_dispatch.c \
	icc_transform.c \
	Lab2XYZ.c \
	Lab2LCh.c \
	LCh2Lab.c \
	LCh2UCS.c \
	UCS2LCh.c \
	XYZ2Lab.c \
	XYZ2Yxy.c \
	Yxy2XYZ.c \
	float2rad.c \
	rad2float.c \
	Lab2LabQ.c \
	LabQ2Lab.c \
	LabS2Lab.c \
	Lab2LabS.c \
	LabS2LabQ.c \
	LabQ2LabS.c \
	LabQ2sRGB.c \
	XYZ2sRGB.c \
	sRGB2XYZ.c \
	im_lab_morph.c \
	im_dE00_fromLab.c \
	im_dECMC_fromLab.c \
	im_dE_fromLab.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
