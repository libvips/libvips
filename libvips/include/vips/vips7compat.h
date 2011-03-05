/* compat with the vips7 API
 *
 * 4/3/11
 * 	- hacked up
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_VIPS7COMPAT_H
#define VIPS_VIP7COMPATS_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Renamed types.
 */

#define IM_BANDFMT_NOTSET VIPS_FORMAT_NOTSET
#define IM_BANDFMT_UCHAR VIPS_FORMAT_UCHAR
#define IM_BANDFMT_CHAR VIPS_FORMAT_CHAR
#define IM_BANDFMT_USHORT VIPS_FORMAT_USHORT
#define IM_BANDFMT_SHORT VIPS_FORMAT_SHORT
#define IM_BANDFMT_UINT VIPS_FORMAT_UINT
#define IM_BANDFMT_INT VIPS_FORMAT_INT
#define IM_BANDFMT_FLOAT VIPS_FORMAT_FLOAT
#define IM_BANDFMT_COMPLEX VIPS_FORMAT_COMPLEX
#define IM_BANDFMT_DOUBLE VIPS_FORMAT_DOUBLE
#define IM_BANDFMT_DPCOMPLEX VIPS_FORMAT_DPCOMPLEX
#define IM_BANDFMT_LAST VIPS_FORMAT_LAST
#define VipsBandFmt VipsBandFormat

#define IM_SMALLTILE VIPS_DEMAND_STYLE_SMALLTILE
#define IM_FATSTRIP VIPS_DEMAND_STYLE_FATSTRIP
#define IM_THINSTRIP VIPS_DEMAND_STYLE_THINSTRIP
#define IM_ANY VIPS_DEMAND_STYLE_ANY

#define IM_CODING_NONE VIPS_CODING_NONE
#define IM_CODING_LABQ VIPS_CODING_LABQ
#define IM_CODING_RAD VIPS_CODING_RAD

#define IM_TYPE_MULTIBAND VIPS_INTERPRETATION_MULTIBAND
#define IM_TYPE_B_W VIPS_INTERPRETATION_B_W
#define IM_TYPE_HISTOGRAM VIPS_INTERPRETATION_HISTOGRAM
#define IM_TYPE_FOURIER VIPS_INTERPRETATION_FOURIER
#define IM_TYPE_XYZ VIPS_INTERPRETATION_XYZ
#define IM_TYPE_LAB VIPS_INTERPRETATION_LAB
#define IM_TYPE_CMYK VIPS_INTERPRETATION_CMYK
#define IM_TYPE_LABQ VIPS_INTERPRETATION_LABQ
#define IM_TYPE_RGB VIPS_INTERPRETATION_RGB
#define IM_TYPE_UCS VIPS_INTERPRETATION_UCS
#define IM_TYPE_LCH VIPS_INTERPRETATION_LCH
#define IM_TYPE_LABS VIPS_INTERPRETATION_LABS
#define IM_TYPE_sRGB VIPS_INTERPRETATION_sRGB
#define IM_TYPE_YXY VIPS_INTERPRETATION_YXY
#define IM_TYPE_RGB16 VIPS_INTERPRETATION_RGB16
#define IM_TYPE_GREY16 VIPS_INTERPRETATION_GREY16
#define VipsType VipsInterpretation

#define IMAGE VipsImage
#define REGION VipsRegion

/* Renamed macros.
 */

#define IM_MAX VIPS_MAX
#define IM_MIN VIPS_MIN
#define IM_RAD VIPS_RAD
#define IM_DEG VIPS_DEG
#define IM_PI VIPS_PI
#define IM_RINT VIPS_RINT
#define IM_NEW VIPS_NEW
#define IM_ARRAY VIPS_ARRAY
#define IM_FREE VIPS_FREE
#define IM_FREEF VIPS_FREEF
#define IM_NUMBER VIPS_NUMBER
#define IM_CLIP VIPS_CLIP
#define IM_CLIP_UCHAR VIPS_CLIP_UCHAR
#define IM_CLIP_CHAR VIPS_CLIP_CHAR
#define IM_CLIP_USHORT VIPS_CLIP_USHORT
#define IM_CLIP_SHORT VIPS_CLIP_SHORT
#define IM_CLIP_NONE VIPS_CLIP_NONE
#define IM_UNROLL VIPS_UNROLL
#define IM_SWAP VIPS_SWAP

#define IM_IMAGE_ADDR VIPS_IMAGE_ADDR
#define IM_IMAGE_N_ELEMENTS VIPS_IMAGE_N_ELEMENTS
#define IM_IMAGE_SIZEOF_ELEMENT VIPS_IMAGE_SIZEOF_ELEMENT
#define IM_IMAGE_SIZEOF_PEL VIPS_IMAGE_SIZEOF_PEL
#define IM_IMAGE_SIZEOF_LINE VIPS_IMAGE_SIZEOF_LINE

#define IM_REGION_LSKIP VIPS_REGION_LSKIP
#define IM_REGION_ADDR VIPS_REGION_ADDR
#define IM_REGION_ADDR_TOPLEFT VIPS_REGION_ADDR_TOPLEFT
#define IM_REGION_N_ELEMENTS VIPS_REGION_N_ELEMENTS
#define IM_REGION_SIZEOF_LINE VIPS_REGION_SIZEOF_LINE

/* Renamed externs.
 */

#define im__sizeof_bandfmt vips__image_sizeof_bandformat

/* Renamed functions.
 */

#define im_error vips_error
#define im_verror vips_verror
#define im_verror_system vips_verror_system
#define im_error_system vips_error_system
#define im_error_buffer vips_error_buffer
#define im_error_clear vips_error_clear
#define im_warn vips_warn
#define im_vwarn vips_vwarn
#define im_diag vips_diag
#define im_vdiag vips_vdiag
#define error_exit vips_error_exit

#define im_get_argv0 vips_get_argv0
#define im_version_string vips_version_string
#define im_version vips_version
#define im_init_world vips_init
#define im_get_option_group vips_get_option_group
#define im_guess_prefix vips_guess_prefix
#define im_guess_libdir vips_guess_libdir
#define im__global_lock vips__global_lock

#define im_cp_desc vips_image_copy_fields
#define im_cp_descv vips_image_copy_fieldsv
#define im_cp_desc_array vips_image_copy_fields_array
#define im_open vips_image_new_from_file
#define im_image vips_image_new_from_memory
#define im_binfile vips_image_new_from_file_raw
#define im__open_temp vips_image_new_disc_temp
#define im__test_kill( I ) (!vips_image_get_kill( I ))
#define im__start_eval( I ) (vips_image_preeval( I ), !vips_image_get_kill( I ))
#define im__handle_eval( I, W, H ) \
	(vips_image_eval( I, W, H ), !vips_image_get_kill( I ))
#define im__end_eval vips_image_posteval
#define im_invalidate vips_image_invalidate_all
#define im_isfile vips_image_isfile
#define im_printdesc( I ) vips_object_print( VIPS_OBJECT( I ) )
#define im_openout( F ) vips_image_new_from_file( F, "w" )
#define im_setbuf( F ) vips_image_new( "t" )

#define im_initdesc( image, \
	xsize, ysize, bands, bandbits, bandfmt, coding, \
	type, xres, yres, xo, yo ) \
	vips_image_init_fields( image, \
		xsize, ysize, bands, bandfmt, coding, \
		type, xres, yres, xo, yo )

#define im_writeline( Y, IM, P ) vips_image_write_line( IM, Y, P )

#define im_prepare vips_region_prepare
#define im_prepare_to vips_region_prepare_to
#define im_region_create vips_region_new
#define im_region_free g_object_unref
#define im_region_region vips_region_region
#define im_region_buffer vips_region_buffer
#define im_region_black vips_region_black
#define im_region_paint vips_region_paint
#define im_prepare_many vips_region_prepare_many

#define im__region_no_ownership vips__region_no_ownership

/* Compat functions.
 */

VipsImage *im_open_local( VipsImage *parent, 
	const char *filename, const char *mode );
int im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n, const char *filename, const char *mode );

/* uncomment this when we remove the im_callback_fn from meta.h
typedef int (*im_callback_fn)( void *a, void *b );
 */

int im_add_callback( VipsImage *im, 
	const char *callback, im_callback_fn fn, void *a, void *b );
#define im_add_close_callback( IM, FN, A, B ) \
	im_add_callback( IM, "close", FN, A, B )
#define im_add_postclose_callback( IM, FN, A, B ) \
	im_add_callback( IM, "postclose", FN, A, B )
#define im_add_evalstart_callback( IM, FN, A, B ) \
	im_add_callback( IM, "evalstart", FN, A, B )
#define im_add_evalend_callback( IM, FN, A, B ) \
	im_add_callback( IM, "evalend", FN, A, B )
#define im_add_invalidate_callback( IM, FN, A, B ) \
	im_add_callback( IM, "invalidate", FN, A, B )

#define im_bits_of_fmt( fmt ) (vips_format_sizeof( fmt ) << 3)

typedef void *(*im_construct_fn)( void *, void *, void * );
void *im_local( VipsImage *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );
int im_local_array( VipsImage *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );

int im_close( VipsImage *im );
VipsImage *im_init( const char *filename );

const char *im_Type2char( VipsInterpretation type );
const char *im_BandFmt2char( VipsBandFormat fmt );
const char *im_Coding2char( VipsCoding coding );
const char *im_Compression2char( int n );
const char *im_dtype2char( VipsImageType n );
const char *im_dhint2char( VipsDemandStyle style );

VipsInterpretation im_char2Type( const char *str );
VipsBandFormat im_char2BandFmt( const char *str );
VipsCoding im_char2Coding( const char *str );
VipsImageType im_char2dtype( const char *str );
VipsDemandStyle im_char2dhint( const char *str );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VIPS7COMPAT_H*/


