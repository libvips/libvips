# Microsoft Developer Studio Project File - Name="vips" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=vips - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vips.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vips.mak" CFG="vips - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "vips - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vips - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "vips - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VIPS_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "." /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VIPS_EXPORTS" /D "HAVE_CONFIG_H" /YX /FD /I./include /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0xc0a /d "NDEBUG"
# ADD RSC /l 0xc0a /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ./lib/libtiff.lib ./lib/jpeg.lib ./lib/libpng.lib ./lib/zlib.lib /nologo /dll /machine:I386 /nodefaultlib:"libc.lib"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "vips - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VIPS_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VIPS_EXPORTS" /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0xc0a /d "_DEBUG"
# ADD RSC /l 0xc0a /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "vips - Win32 Release"
# Name "vips - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "acquire"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\acquire\im_clamp.c
# End Source File
# End Group
# Begin Group "arithmetic"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\arithmetic\arith_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_abs.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_add.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_avg.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_ceil.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_cmulnorm.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_costra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_deviate.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_divide.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_expntra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_fav4.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_floor.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_gadd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_gaddim.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_gfadd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_invert.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_lintra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_litecor.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_log10tra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_logtra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_max.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_maxpos.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_measure.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_min.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_minpos.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_multiply.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_powtra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_remainder.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_sign.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_sintra.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_stats.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_subtract.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\arithmetic\im_tantra.c
# End Source File
# End Group
# Begin Group "boolean"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\boolean\bool_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\boolean\boolean.c
# End Source File
# End Group
# Begin Group "colour"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\colour\colour.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\colour_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\derived.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_dE00_fromLab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_dE_fromLab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_dECMC_fromLab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_disp2XYZ.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_icc_transform.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_Lab2LabQ.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_Lab2LabS.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_Lab2LCh.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_Lab2XYZ.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_lab_morph.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LabQ2disp.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LabQ2Lab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LabQ2LabS.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LabS2Lab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LabS2LabQ.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LCh2Lab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_LCh2UCS.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_UCS2LCh.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_XYZ2disp.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_XYZ2Lab.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_XYZ2Yxy.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\colour\im_Yxy2XYZ.c
# End Source File
# End Group
# Begin Group "conversion"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\conversion\conver_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_bandjoin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_bernd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_black.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_c2amph.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_c2imag.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_c2ps.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_c2real.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_c2rect.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_clip.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_copy.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_extract.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_falsecolour.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_fliphor.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_flipver.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_gbandjoin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_insert.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_lrjoin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_magick2vips.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_mask2vips.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_ppm2vips.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_print.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_recomb.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_ri2c.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_rot180.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_rot270.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_rot90.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_scale.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_scaleps.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_slice.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_subsample.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_system.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_tbjoin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_thresh.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_tiff2vips.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_vips2mask.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_vips2ppm.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_vips2tiff.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\im_zoom.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\vips_jpeg.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\conversion\vips_png.c
# End Source File
# End Group
# Begin Group "convolution"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\convolution\convol_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_addgnoise.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_compass.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_conv.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_convf.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_convsep.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_convsepf.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_convsub.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_embed.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_fastcor.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_gaussmasks.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_gaussnoise.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_gradient.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_lindetect.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_logmasks.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_maxvalue.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_mpercent.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_rank.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_resize_linear.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_sharpen.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_shrink.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_spcor.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_stretch3.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\im_zerox.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\rotmask.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\convolution\rw_mask.c
# End Source File
# End Group
# Begin Group "freq_filt"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\freq_filt\fft_sp.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\fmask4th.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\fmaskcir.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\freq_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_disp_ps.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_fractsurf.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_freq_mask.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_freqflt.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_fwfft.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_invfft.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_invfftr.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\freq_filt\im_rotquad.c
# End Source File
# End Group
# Begin Group "histograms_lut"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\histograms_lut\hist_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_gammacorrect.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_heq.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_hist.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_histeq.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_histgr.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_histnD.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_histplot.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_histspec.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_hsp.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_identity.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_invertlut.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_lhisteq.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_maplut.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\im_stdif.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\histograms_lut\tone.c
# End Source File
# End Group
# Begin Group "inplace"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\inplace\im_circle.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\im_flood.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\im_insertplace.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\im_line.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\im_paintrect.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\im_plotmask.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\inplace_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\line_draw.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\plot_point.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\inplace\smudge_area.c
# End Source File
# End Group
# Begin Group "iofuncs"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\iofuncs\callback.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\debug.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\dispatch_types.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\error.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\error_exit.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_append_Hist.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_binfile.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_close.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_cp_desc.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_cp_Hist.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_crwrhd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_debugim.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_demand_hint.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_desc_hd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_generate.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_guess_prefix.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_header.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_histlin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_image.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_init.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_initdesc.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_inithd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_iocheck.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_iterate.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_makerw.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_mapfile.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_open.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_openin.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_openout.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_partial.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_piocheck.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_prepare.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_printdesc.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_printhd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_printlines.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_readhist.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_setbox.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_setbuf.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_setupout.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_unmapfile.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_updatehist.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_wrapmany.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_wrapone.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\im_writeline.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\list.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\memory.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\package.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\predicate.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\rect.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\region.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\thread.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\threadgroup.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\iofuncs\time.c
# End Source File
# End Group
# Begin Group "matrix"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\matrix\im_invmat.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\im_matcat.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\im_matinv.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\im_matmul.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\im_mattrn.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\matalloc.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\matrix\matrix_dispatch.c
# End Source File
# End Group
# Begin Group "morphology"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\morphology\im_cntlines.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\morphology\im_dilate.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\morphology\im_erode.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\morphology\im_profile.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\morphology\morph_dispatch.c
# End Source File
# End Group
# Begin Group "mosaicing"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\mosaicing\global_balance.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\global_balance.h
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_affine.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_avgdxdy.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_chkpair.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_clinear.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_improve.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_initialize.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_lrcalcon.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_lrmerge.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_lrmosaic.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_remosaic.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_tbcalcon.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_tbmerge.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\im_tbmosaic.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\match.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\merge.h
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\mosaic.h
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\mosaic1.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\mosaicing_dispatch.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\mosaicing\similarity.c
# End Source File
# End Group
# Begin Group "other"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\other\cooc_funcs.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\glds_funcs.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_dif_std.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_eye.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_grey.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_meanstd.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_simcontr.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_sines.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_spatres.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\im_zone.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\other\other_dispatch.c
# End Source File
# End Group
# Begin Group "relational"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\relational\im_blend.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\relational\im_ifthenelse.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\relational\relational.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\relational\relational_dispatch.c
# End Source File
# End Group
# Begin Group "video"

# PROP Default_Filter ".c"
# Begin Source File

SOURCE=.\libsrc\video\im_video_v4l1.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\video\video_dispatch.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\libsrc\dummy.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\vips.def
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "vips"

# PROP Default_Filter ".h"
# Begin Source File

SOURCE=.\include\vips\colour.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\debug.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\dispatch.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\fmask.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\history.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\list.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\mosaic.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\proto.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\rect.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\region.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\struct.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\thread.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\threadgroup.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\time.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\util.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\version.h
# End Source File
# Begin Source File

SOURCE=.\include\vips\vips.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\config.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
