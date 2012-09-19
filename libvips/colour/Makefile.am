noinst_LTLIBRARIES = libcolour.la

libcolour_la_SOURCES = \
	colour.c \
	colour_funcs.c \
	disp.c \
	colour_dispatch.c \
	derived.c \
	Lab2XYZ.c \
	Lab2LCh.c \
	LCh2Lab.c \
	LCh2UCS.c \
	UCS2LCh.c \
	im_icc_transform.c \
	im_Lab2LabQ.c \
	im_Lab2LabS.c \
	im_LabQ2Lab.c \
	im_LabQ2LabS.c \
	im_LabQ2disp.c \
	im_LabS2LabQ.c \
	im_LabS2Lab.c \
	im_lab_morph.c \
	im_XYZ2Lab.c \
	im_XYZ2Yxy.c \
	im_float2rad.c \
	im_Yxy2XYZ.c \
	im_XYZ2disp.c \
	im_dE00_fromLab.c \
	im_dECMC_fromLab.c \
	im_dE_fromLab.c \
	im_disp2XYZ.c \
	im_rad2float.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
