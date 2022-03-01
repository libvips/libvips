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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_VIPS7COMPAT_H
#define VIPS_VIPS7COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Renamed types.
 */

/* We have this misspelt in earlier versions :(
 */
#define VIPS_META_IPCT_NAME VIPS_META_IPTC_NAME 

#define IM_D93_X0 VIPS_D93_X0 
#define IM_D93_Y0 VIPS_D93_Y0 
#define IM_D93_Z0 VIPS_D93_Z0 

#define IM_D75_X0 VIPS_D75_X0 
#define IM_D75_Y0 VIPS_D75_Y0 
#define IM_D75_Z0 VIPS_D75_Z0 

#define IM_D65_X0 VIPS_D65_X0 
#define IM_D65_Y0 VIPS_D65_Y0 
#define IM_D65_Z0 VIPS_D65_Z0 

#define IM_D55_X0 VIPS_D55_X0 
#define IM_D55_Y0 VIPS_D55_Y0 
#define IM_D55_Z0 VIPS_D55_Z0 

#define IM_D50_X0 VIPS_D50_X0 
#define IM_D50_Y0 VIPS_D50_Y0 
#define IM_D50_Z0 VIPS_D50_Z0 

#define IM_A_X0 VIPS_A_X0 
#define IM_A_Y0 VIPS_A_Y0 
#define IM_A_Z0 VIPS_A_Z0 

#define IM_B_X0 VIPS_B_X0 
#define IM_B_Y0 VIPS_B_Y0 
#define IM_B_Z0 VIPS_B_Z0 

#define IM_C_X0 VIPS_C_X0 
#define IM_C_Y0 VIPS_C_Y0 
#define IM_C_Z0 VIPS_C_Z0 

#define IM_E_X0 VIPS_E_X0 
#define IM_E_Y0 VIPS_E_Y0 
#define IM_E_Z0 VIPS_E_Z0 

#define IM_D3250_X0 VIPS_D3250_X0 
#define IM_D3250_Y0 VIPS_D3250_Y0 
#define IM_D3250_Z0 VIPS_D3250_Z0 

#define im_col_Lab2XYZ vips_col_Lab2XYZ
#define im_col_XYZ2Lab vips_col_XYZ2Lab
#define im_col_ab2h vips_col_ab2h
#define im_col_ab2Ch vips_col_ab2Ch
#define im_col_Ch2ab vips_col_Ch2ab

#define im_col_L2Lucs vips_col_L2Lcmc
#define im_col_C2Cucs vips_col_C2Ccmc
#define im_col_Ch2hucs vips_col_Ch2hcmc
#define im_col_pythagoras vips_pythagoras

#define im_col_make_tables_UCS vips_col_make_tables_CMC
#define im_col_Lucs2L vips_col_Lcmc2L
#define im_col_Cucs2C vips_col_Ccmc2C
#define im_col_Chucs2h vips_col_Chcmc2h

#define PEL VipsPel

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
#define IM_TYPE_UCS VIPS_INTERPRETATION_CMC
#define IM_TYPE_LCH VIPS_INTERPRETATION_LCH
#define IM_TYPE_LABS VIPS_INTERPRETATION_LABS
#define IM_TYPE_sRGB VIPS_INTERPRETATION_sRGB
#define IM_TYPE_YXY VIPS_INTERPRETATION_YXY
#define IM_TYPE_RGB16 VIPS_INTERPRETATION_RGB16
#define IM_TYPE_GREY16 VIPS_INTERPRETATION_GREY16
#define VipsType VipsInterpretation

#define IMAGE VipsImage
#define REGION VipsRegion

#define IM_INTENT_PERCEPTUAL VIPS_INTENT_PERCEPTUAL
#define IM_INTENT_RELATIVE_COLORIMETRIC VIPS_INTENT_RELATIVE
#define IM_INTENT_SATURATION VIPS_INTENT_SATURATION
#define IM_INTENT_ABSOLUTE_COLORIMETRIC VIPS_INTENT_ABSOLUTE

/* Renamed macros.
 */

#define IM_MAX VIPS_MAX
#define IM_MIN VIPS_MIN
#define IM_RAD VIPS_RAD
#define IM_DEG VIPS_DEG
#define IM_PI VIPS_PI
#define IM_RINT VIPS_RINT
#define IM_ABS VIPS_ABS
#define IM_NUMBER VIPS_NUMBER
#define IM_CLIP VIPS_CLIP
#define IM_CLIP_UCHAR VIPS_CLIP_UCHAR
#define IM_CLIP_CHAR VIPS_CLIP_CHAR
#define IM_CLIP_USHORT VIPS_CLIP_USHORT
#define IM_CLIP_SHORT VIPS_CLIP_SHORT
#define IM_CLIP_NONE VIPS_CLIP_NONE
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
VIPS_DEPRECATED_FOR(vips_format_sizeof_unsafe)
const guint64 vips__image_sizeof_bandformat[];
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
#define im_diag vips_info
#define im_vdiag vips_vinfo
#define error_exit vips_error_exit

#define im_get_argv0 vips_get_argv0
#define im_version_string vips_version_string
#define im_version vips_version
#define im_get_option_group vips_get_option_group
#define im_guess_prefix vips_guess_prefix
#define im_guess_libdir vips_guess_libdir
#define im__global_lock vips__global_lock

VIPS_DEPRECATED
int im_cp_desc(IMAGE *out, IMAGE *in );
VIPS_DEPRECATED
int im_cp_descv (IMAGE * im, ...);
#define im_cp_desc_array(I, A) vips__image_copy_fields_array(I, A)
VIPS_DEPRECATED
int im_demand_hint (IMAGE * im, VipsDemandStyle hint, ...);
#define im_demand_hint_array( A, B, C ) (vips__demand_hint_array( A, B, C ), 0)

#define im_image(P, W, H, B, F) \
	vips_image_new_from_memory((P), 0, (W), (H), (B), (F))

#define im_binfile vips_image_new_from_file_raw
#define im__open_temp vips_image_new_temp_file
#define im__test_kill( I ) (vips_image_iskilled( I ))
#define im__start_eval( I ) (vips_image_preeval( I ), vips_image_iskilled( I ))
#define im__handle_eval( I, W, H ) \
	(vips_image_eval( I, W, H ), vips_image_iskilled( I ))
#define im__end_eval vips_image_posteval
#define im_invalidate vips_image_invalidate_all
#define im_isfile vips_image_isfile
#define im_printdesc( I ) vips_object_print_dump( VIPS_OBJECT( I ) )

/* im_openout() needs to have this visible.
 */
VIPS_DEPRECATED
VipsImage *vips_image_new_mode( const char *filename, const char *mode );

/* im_image_open_input() needs to have this visible.
 */
VIPS_DEPRECATED
int vips_image_open_input( VipsImage *image );

/* im_image_open_output() needs to have this visible.
 */
VIPS_DEPRECATED
int vips_image_open_output( VipsImage *image );

/* im_mapfile() needs to have this visible.
 */
VIPS_DEPRECATED
int vips_mapfile( VipsImage *image );

/* im_mapfilerw() needs to have this visible.
 */
VIPS_DEPRECATED
int vips_mapfilerw( VipsImage *image );

/* im_remapfilerw() needs to have this visible.
 */
VIPS_DEPRECATED
int vips_remapfilerw( VipsImage *image );

#define im_openout( F ) vips_image_new_mode( F, "w" )
#define im_setbuf( F ) vips_image_new( "t" )

#define im_initdesc( image, \
	xsize, ysize, bands, bandbits, bandfmt, coding, \
	type, xres, yres, xo, yo ) \
	vips_image_init_fields( image, \
		xsize, ysize, bands, bandfmt, coding, \
		type, xres, yres )

#define im__open_image_file vips__open_image_read
#define im_setupout vips_image_write_prepare
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

#define im_image_sanity( I ) (!vips_object_sanity( VIPS_OBJECT( I ) ))
#define im_image_sanity_all vips_object_sanity_all
#define im__print_all vips_object_print_all

/* Compat functions.
 */

VIPS_DEPRECATED_FOR(vips_init)
int im_init_world( const char *argv0 ); 

VIPS_DEPRECATED_FOR(vips_image_new_mode)
VipsImage *im_open( const char *filename, const char *mode );

VIPS_DEPRECATED
VipsImage *im_open_local( VipsImage *parent, 
	const char *filename, const char *mode );
VIPS_DEPRECATED
int im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n, const char *filename, const char *mode );

#define im_callback_fn VipsCallbackFn

VIPS_DEPRECATED_FOR(g_signal_connect)
int im_add_callback( VipsImage *im, 
	const char *callback, im_callback_fn fn, void *a, void *b );
VIPS_DEPRECATED_FOR(g_signal_connect)
int im_add_callback1( VipsImage *im, 
	const char *callback, im_callback_fn fn, void *a, void *b );
#define im_add_close_callback( IM, FN, A, B ) \
	im_add_callback( IM, "close", FN, A, B )
#define im_add_postclose_callback( IM, FN, A, B ) \
	im_add_callback( IM, "postclose", FN, A, B )
#define im_add_preclose_callback( IM, FN, A, B ) \
	im_add_callback( IM, "preclose", FN, A, B )
#define im_add_evalstart_callback( IM, FN, A, B ) \
	im_add_callback1( IM, "preeval", FN, A, B )
#define im_add_evalend_callback( IM, FN, A, B ) \
	im_add_callback1( IM, "posteval", FN, A, B )
#define im_add_eval_callback( IM, FN, A, B ) \
	(vips_image_set_progress( IM, TRUE ), \
	im_add_callback1( IM, "eval", FN, A, B ))
#define im_add_invalidate_callback( IM, FN, A, B ) \
	im_add_callback( IM, "invalidate", FN, A, B )

#define im_bits_of_fmt( fmt ) (vips_format_sizeof( fmt ) << 3)

typedef void *(*im_construct_fn)( void *, void *, void * );
VIPS_DEPRECATED_FOR(vips_object_local)
void *im_local( VipsImage *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );
VIPS_DEPRECATED_FOR(vips_object_local_array)
int im_local_array( VipsImage *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );

VIPS_DEPRECATED_FOR(g_object_unref)
int im_close( VipsImage *im );
VIPS_DEPRECATED_FOR(vips_image_new_from_file)
VipsImage *im_init( const char *filename );

VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_Type2char( VipsInterpretation type );
VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_BandFmt2char( VipsBandFormat fmt );
VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_Coding2char( VipsCoding coding );
VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_Compression2char( int n );
VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_dtype2char( VipsImageType n );
VIPS_DEPRECATED_FOR(vips_enum_string)
const char *im_dhint2char( VipsDemandStyle style );

VIPS_DEPRECATED_FOR(vips_enum_from_nick)
VipsInterpretation im_char2Type( const char *str );
VIPS_DEPRECATED_FOR(vips_enum_from_nick)
VipsBandFormat im_char2BandFmt( const char *str );
VIPS_DEPRECATED_FOR(vips_enum_from_nick)
VipsCoding im_char2Coding( const char *str );
VIPS_DEPRECATED_FOR(vips_enum_from_nick)
VipsImageType im_char2dtype( const char *str );
VIPS_DEPRECATED_FOR(vips_enum_from_nick)
VipsDemandStyle im_char2dhint( const char *str );

#define Rect VipsRect
#define IM_RECT_RIGHT VIPS_RECT_RIGHT
#define IM_RECT_BOTTOM VIPS_RECT_BOTTOM
#define IM_RECT_HCENTRE VIPS_RECT_HCENTRE
#define IM_RECT_VCENTRE VIPS_RECT_VCENTRE

#define im_rect_marginadjust vips_rect_marginadjust
#define im_rect_includespoint vips_rect_includespoint
#define im_rect_includesrect vips_rect_includesrect
#define im_rect_intersectrect vips_rect_intersectrect
#define im_rect_isempty vips_rect_isempty
#define im_rect_unionrect vips_rect_unionrect
#define im_rect_equalsrect vips_rect_equalsrect
#define im_rect_dup vips_rect_dup
#define im_rect_normalise vips_rect_normalise

#define im_start_one vips_start_one
#define im_stop_one vips_stop_one
#define im_start_many vips_start_many
#define im_stop_many vips_stop_many
#define im_allocate_input_array vips_allocate_input_array
#define im_start_fn VipsStartFn
typedef int (*im_generate_fn)( VipsRegion *out, void *seq, void *a, void *b );
#define im_stop_fn VipsStopFn
VIPS_DEPRECATED_FOR(vips_image_generate)
int im_generate( VipsImage *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b );

#define im__mmap vips__mmap
#define im__munmap vips__munmap
#define im_mapfile vips_mapfile
#define im_mapfilerw vips_mapfilerw
#define im_remapfilerw vips_remapfilerw

#define im__print_renders vips__print_renders

VIPS_DEPRECATED_FOR(vips_sink_screen)
int im_cache( IMAGE *in, IMAGE *out, int width, int height, int max );

#define IM_FREEF( F, S ) \
G_STMT_START { \
        if( S ) { \
                (void) F( (S) ); \
                (S) = 0; \
        } \
} G_STMT_END

/* Can't just use VIPS_FREEF(), we want the extra cast to void on the argument
 * to vips_free() to make sure we can work for "const char *" variables.
 */
#define IM_FREE( S ) \
G_STMT_START { \
        if( S ) { \
                (void) im_free( (void *) (S) ); \
                (S) = 0; \
        } \
} G_STMT_END

#define IM_SETSTR( S, V ) \
G_STMT_START { \
        const char *sst = (V); \
	\
        if( (S) != sst ) { \
                if( !(S) || !sst || strcmp( (S), sst ) != 0 ) { \
                        IM_FREE( S ); \
                        if( sst ) \
                                (S) = im_strdup( NULL, sst ); \
                } \
        } \
} G_STMT_END

#define im_malloc( IM, SZ ) \
	(vips_malloc( VIPS_OBJECT( IM ), (SZ) ))
#define im_free vips_free
#define im_strdup( IM, STR ) \
	(vips_strdup( VIPS_OBJECT( IM ), (STR) ))
#define IM_NEW( IM, T ) ((T *) im_malloc( (IM), sizeof( T )))
#define IM_ARRAY( IM, N, T ) ((T *) im_malloc( (IM), (N) * sizeof( T )))

#define im_incheck vips_image_wio_input
#define im_outcheck( I ) (0)
#define im_rwcheck vips_image_inplace
#define im_pincheck vips_image_pio_input
#define im_poutcheck( I ) (0)

#define im_iocheck( I, O ) im_incheck( I )
#define im_piocheck( I, O ) im_pincheck( I )

#define im_check_uncoded vips_check_uncoded 
#define im_check_coding_known vips_check_coding_known 
#define im_check_coding_labq vips_check_coding_labq 
#define im_check_coding_rad vips_check_coding_rad 
#define im_check_coding_noneorlabq vips_check_coding_noneorlabq 
#define im_check_coding_same vips_check_coding_same 
#define im_check_mono vips_check_mono 
#define im_check_bands_1or3 vips_check_bands_1or3 
#define im_check_bands vips_check_bands 
#define im_check_bands_1orn vips_check_bands_1orn 
#define im_check_bands_1orn_unary vips_check_bands_1orn_unary 
#define im_check_bands_same vips_check_bands_same 
#define im_check_bandno vips_check_bandno 
#define im_check_int vips_check_int 
#define im_check_uint vips_check_uint 
#define im_check_uintorf vips_check_uintorf 
#define im_check_noncomplex vips_check_noncomplex 
#define im_check_complex vips_check_complex 
#define im_check_format vips_check_format 
#define im_check_u8or16 vips_check_u8or16 
#define im_check_8or16 vips_check_8or16 
#define im_check_u8or16orf vips_check_u8or16orf 
#define im_check_format_same vips_check_format_same 
#define im_check_size_same vips_check_size_same 
#define im_check_vector vips_check_vector 
#define im_check_hist vips_check_hist 
#define im_check_imask vips_check_imask 
#define im_check_dmask vips_check_dmask 

#define vips_bandfmt_isint vips_band_format_isint 
#define vips_bandfmt_isuint vips_band_format_isuint 
#define vips_bandfmt_isfloat vips_band_format_isfloat 
#define vips_bandfmt_iscomplex vips_band_format_iscomplex 

#define im__change_suffix vips__change_suffix

/* Buffer processing.
 */
typedef void (*im_wrapone_fn)( void *in, void *out, int width,
	void *a, void *b );
VIPS_DEPRECATED
int im_wrapone( VipsImage *in, VipsImage *out,
	im_wrapone_fn fn, void *a, void *b );

typedef void (*im_wraptwo_fn)( void *in1, void *in2, void *out, 
        int width, void *a, void *b );
VIPS_DEPRECATED
int im_wraptwo( VipsImage *in1, VipsImage *in2, VipsImage *out,
	im_wraptwo_fn fn, void *a, void *b );

typedef void (*im_wrapmany_fn)( void **in, void *out, int width,
	void *a, void *b );
VIPS_DEPRECATED
int im_wrapmany( VipsImage **in, VipsImage *out,
	im_wrapmany_fn fn, void *a, void *b );

#define IM_META_EXIF_NAME VIPS_META_EXIF_NAME 
#define IM_META_ICC_NAME VIPS_META_ICC_NAME 
#define IM_META_RESOLUTION_UNIT VIPS_META_RESOLUTION_UNIT 
#define IM_TYPE_SAVE_STRING VIPS_TYPE_SAVE_STRING 
#define IM_TYPE_BLOB VIPS_TYPE_BLOB 
#define IM_TYPE_AREA VIPS_TYPE_AREA 
#define IM_TYPE_REF_STRING VIPS_TYPE_REF_STRING 

#define im_header_map_fn VipsImageMapFn
#define im_header_map vips_image_map

#define im_header_int vips_image_get_int
#define im_header_double vips_image_get_double
#define im_header_string( IMAGE, FIELD, STRING ) \
	vips_image_get_string( IMAGE, FIELD, (const char **) STRING )
#define im_header_as_string vips_image_get_as_string
#define im_header_get_typeof vips_image_get_typeof
#define im_header_get vips_image_get

#define im_histlin vips_image_history_printf
#define im_updatehist vips_image_history_args
#define im_history_get vips_image_get_history

#define im_save_string_get vips_value_get_save_string
#define im_save_string_set vips_value_set_save_string
#define im_save_string_setf vips_value_set_save_stringf

#define im_ref_string_set vips_value_set_ref_string
#define im_ref_string_get( V ) vips_value_get_ref_string( V, NULL )
VIPS_DEPRECATED_FOR(vips_value_get_ref_string)
size_t im_ref_string_get_length( const GValue *value );

#define im_blob_get vips_value_get_blob
#define im_blob_set vips_value_set_blob

#define im_meta_set( A, B, C ) (vips_image_set( A, B, C ), 0)
#define im_meta_remove vips_image_remove
#define im_meta_get vips_image_get
#define im_meta_get_typeof vips_image_get_typeof

#define im_meta_set_int( A, B, C ) (vips_image_set_int( A, B, C ), 0)
#define im_meta_get_int vips_image_get_int
#define im_meta_set_double( A, B, C ) (vips_image_set_double( A, B, C ), 0)
#define im_meta_get_double vips_image_get_double
#define im_meta_set_area( A, B, C, D ) (vips_image_set_area( A, B, C, D ), 0)
#define im_meta_get_area vips_image_get_area
#define im_meta_set_string( A, B, C ) (vips_image_set_string( A, B, C ), 0)
#define im_meta_get_string vips_image_get_string
#define im_meta_set_blob( A, B, C, D, E ) \
	(vips_image_set_blob( A, B, C, D, E ), 0)
#define im_meta_get_blob vips_image_get_blob

#define im_semaphore_t VipsSemaphore

#define im_semaphore_up vips_semaphore_up
#define im_semaphore_down vips_semaphore_down
#define im_semaphore_upn vips_semaphore_upn
#define im_semaphore_downn vips_semaphore_downn
#define im_semaphore_destroy vips_semaphore_destroy
#define im_semaphore_init vips_semaphore_init

#define im__open_image_read vips__open_image_read
#define im_image_open_input vips_image_open_input
#define im_image_open_output vips_image_open_output
#define im__has_extension_block vips__has_extension_block
#define im__read_extension_block vips__read_extension_block
#define im__write_extension_block vips__write_extension_block
#define im__writehist vips__writehist
#define im__read_header_bytes vips__read_header_bytes
#define im__write_header_bytes vips__write_header_bytes

#define VSListMap2Fn VipsSListMap2Fn
#define VSListMap4Fn VipsSListMap4Fn
#define VSListFold2Fn VipsSListFold2Fn

#define im_slist_equal vips_slist_equal
#define im_slist_map2 vips_slist_map2
#define im_slist_map2_rev vips_slist_map2_rev
#define im_slist_map4 vips_slist_map4
#define im_slist_fold2 vips_slist_fold2
#define im_slist_filter vips_slist_filter
#define im_slist_free_all vips_slist_free_all
#define im_map_equal vips_map_equal
#define im_hash_table_map vips_hash_table_map
#define im_strncpy vips_strncpy
#define im_strrstr vips_strrstr
#define im_ispostfix vips_ispostfix
#define im_isprefix vips_isprefix
#define im_break_token vips_break_token
#define im_vsnprintf vips_vsnprintf
#define im_snprintf vips_snprintf
#define im_file_length vips_file_length
#define im__write vips__write
#define im__file_open_read vips__file_open_read
#define im__file_open_write vips__file_open_write
#define im__file_read vips__file_read
#define im__file_read_name vips__file_read_name
#define im__file_write vips__file_write
#define im__get_bytes vips__get_bytes
#define im__gvalue_ref_string_new vips__gvalue_ref_string_new
#define im__gslist_gvalue_free vips__gslist_gvalue_free
#define im__gslist_gvalue_copy vips__gslist_gvalue_copy
#define im__gslist_gvalue_merge vips__gslist_gvalue_merge
#define im__gslist_gvalue_get vips__gslist_gvalue_get
#define im__seek vips__seek
#define im__ftruncate vips__ftruncate
#define im_existsf vips_existsf
#define im_popenf vips_popenf
#define im_ispoweroftwo vips_ispoweroftwo
#define im_amiMSBfirst vips_amiMSBfirst
#define im__temp_name vips__temp_name

#define IM_VERSION_STRING VIPS_VERSION_STRING
#define IM_MAJOR_VERSION VIPS_MAJOR_VERSION
#define IM_MINOR_VERSION VIPS_MINOR_VERSION
#define IM_MICRO_VERSION VIPS_MICRO_VERSION

#if defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)
#define VIPS_EXEEXT ".exe"
#else /* !defined(G_PLATFORM_WIN32) && !defined(G_WITH_CYGWIN) */
#define VIPS_EXEEXT ""
#endif /* defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN) */
#define IM_EXEEXT VIPS_EXEEXT

#define IM_SIZEOF_HEADER VIPS_SIZEOF_HEADER

#define im_concurrency_set vips_concurrency_set
#define im_concurrency_get vips_concurrency_get

VIPS_DEPRECATED_FOR(vips_add)
int im_add( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_subtract)
int im_subtract( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_multiply)
int im_multiply( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_divide)
int im_divide( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_min)
int im_min( VipsImage *in, double *out );
VIPS_DEPRECATED_FOR(vips_min)
int im_minpos( VipsImage *in, int *xpos, int *ypos, double *out );
VIPS_DEPRECATED_FOR(vips_max)
int im_max( VipsImage *in, double *out );
VIPS_DEPRECATED_FOR(vips_max)
int im_maxpos( VipsImage *in, int *xpos, int *ypos, double *out );
VIPS_DEPRECATED_FOR(vips_avg)
int im_avg( VipsImage *in, double *out );
VIPS_DEPRECATED_FOR(vips_deviate)
int im_deviate( VipsImage *in, double *out );
VIPS_DEPRECATED_FOR(vips_invert)
int im_invert( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_linear1)
int im_lintra( double a, VipsImage *in, double b, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_linear)
int im_lintra_vec( int n, double *a, VipsImage *in, double *b, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_abs)
int im_abs( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_sign)
int im_sign( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_stats)
DOUBLEMASK *im_stats( VipsImage *in );
VIPS_DEPRECATED_FOR(vips_measure)
DOUBLEMASK *im_measure_area( VipsImage *im, 
	int left, int top, int width, int height, 
	int h, int v, 
	int *sel, int nsel, const char *name );

VIPS_DEPRECATED_FOR(vips_sin)
int im_sintra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_cos)
int im_costra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_tan)
int im_tantra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_asin)
int im_asintra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_acos)
int im_acostra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_atan)
int im_atantra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_log)
int im_logtra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_log10)
int im_log10tra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_exp)
int im_exptra( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_exp10)
int im_exp10tra( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_floor)
int im_floor( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_rint)
int im_rint( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_ceil)
int im_ceil( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_equal)
int im_equal( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_notequal)
int im_notequal( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_less)
int im_less( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_lesseq)
int im_lesseq( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_more)
int im_more( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_moreeq)
int im_moreeq( VipsImage *in1, VipsImage *in2, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_andimage)
int im_andimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_orimage)
int im_orimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_eorimage)
int im_eorimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_andimage_const)
int im_andimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_orimage_const)
int im_orimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_eorimage_const)
int im_eorimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_andimage_const1)
int im_andimageconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_orimage_const1)
int im_orimageconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_eorimage_const1)
int im_eorimageconst( VipsImage *in, VipsImage *out, double c );

VIPS_DEPRECATED_FOR(vips_lshift_const)
int im_shiftleft_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_lshift)
int im_shiftleft( VipsImage *in, VipsImage *out, int n );
VIPS_DEPRECATED_FOR(vips_rshift_const)
int im_shiftright_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_rshift)
int im_shiftright( VipsImage *in, VipsImage *out, int n );

VIPS_DEPRECATED_FOR(vips_remainder)
int im_remainder( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_remainder_const)
int im_remainder_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_remainder_const1)
int im_remainderconst( VipsImage *in, VipsImage *out, double c );

VIPS_DEPRECATED_FOR(vips_pow)
int im_powtra( VipsImage *in, VipsImage *out, double e );
VIPS_DEPRECATED_FOR(vips_pow_const)
int im_powtra_vec( VipsImage *in, VipsImage *out, int n, double *e );
VIPS_DEPRECATED_FOR(vips_exp)
int im_expntra( VipsImage *in, VipsImage *out, double e );
VIPS_DEPRECATED_FOR(vips_exp_const)
int im_expntra_vec( VipsImage *in, VipsImage *out, int n, double *e );

VIPS_DEPRECATED_FOR(vips_equal_const)
int im_equal_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_notequal_const)
int im_notequal_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_less_const)
int im_less_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_lesseq_const)
int im_lesseq_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_more_const)
int im_more_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_moreeq_const)
int im_moreeq_vec( VipsImage *in, VipsImage *out, int n, double *c );
VIPS_DEPRECATED_FOR(vips_equal_const1)
int im_equalconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_notequal_const1)
int im_notequalconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_less_const1)
int im_lessconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_lesseq_const1)
int im_lesseqconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_more_const1)
int im_moreconst( VipsImage *in, VipsImage *out, double c );
VIPS_DEPRECATED_FOR(vips_moreeq_const1)
int im_moreeqconst( VipsImage *in, VipsImage *out, double c );

VIPS_DEPRECATED_FOR(vips_max)
int im_maxpos_vec( VipsImage *im, int *xpos, int *ypos, double *maxima, int n );
VIPS_DEPRECATED_FOR(vips_min)
int im_minpos_vec( VipsImage *im, int *xpos, int *ypos, double *minima, int n );

VIPS_DEPRECATED
int im_maxpos_avg( VipsImage *im, double *xpos, double *ypos, double *out );

VIPS_DEPRECATED
int im_linreg( VipsImage **ins, VipsImage *out, double *xs );

VIPS_DEPRECATED_FOR(vips_cross_phase)
int im_cross_phase( VipsImage *a, VipsImage *b, VipsImage *out );

VIPS_DEPRECATED
int im_point( VipsImage *im, VipsInterpolate *interpolate, 
	double x, double y, int band, double *out );
VIPS_DEPRECATED
int im_point_bilinear( VipsImage *im, 
	double x, double y, int band, double *out );

VIPS_DEPRECATED_FOR(vips_image_write)
int im_copy( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_copy)
int im_copy_set( VipsImage *in, VipsImage *out, 
	VipsInterpretation interpretation, 
	float xres, float yres, int xoffset, int yoffset );
VIPS_DEPRECATED
int im_copy_set_meta( VipsImage *in, VipsImage *out, 
	const char *field, GValue *value );
VIPS_DEPRECATED_FOR(vips_copy)
int im_copy_morph( VipsImage *in, VipsImage *out, 
	int bands, VipsBandFormat format, VipsCoding coding );
VIPS_DEPRECATED_FOR(vips_byteswap)
int im_copy_swap( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_copy_file)
int im_copy_file( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_copy_native( VipsImage *in, VipsImage *out, gboolean is_msb_first );
VIPS_DEPRECATED_FOR(vips_embed)
int im_embed( VipsImage *in, VipsImage *out, 
	int type, int x, int y, int width, int height );
VIPS_DEPRECATED_FOR(vips_flip)
int im_fliphor( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_flip)
int im_flipver( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_insert)
int im_insert( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
VIPS_DEPRECATED_FOR(vips_insert)
int im_insert_noexpand( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
VIPS_DEPRECATED_FOR(vips_join)
int im_lrjoin( VipsImage *left, VipsImage *right, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_join)
int im_tbjoin( VipsImage *top, VipsImage *bottom, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_extract_area)
int im_extract_area( VipsImage *in, VipsImage *out, 
	int left, int top, int width, int height );
VIPS_DEPRECATED_FOR(vips_extract_band)
int im_extract_band( VipsImage *in, VipsImage *out, int band );
VIPS_DEPRECATED_FOR(vips_extract_band)
int im_extract_bands( VipsImage *in, VipsImage *out, int band, int nbands );
VIPS_DEPRECATED
int im_extract_areabands( VipsImage *in, VipsImage *out,
	int left, int top, int width, int height, int band, int nbands );
VIPS_DEPRECATED_FOR(vips_replicate)
int im_replicate( VipsImage *in, VipsImage *out, int across, int down );
VIPS_DEPRECATED_FOR(vips_wrap)
int im_wrap( VipsImage *in, VipsImage *out, int x, int y );
VIPS_DEPRECATED_FOR(vips_wrap)
int im_rotquad( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2fmt( VipsImage *in, VipsImage *out, VipsBandFormat fmt );
VIPS_DEPRECATED_FOR(vips_bandjoin2)
int im_bandjoin( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_bandjoin)
int im_gbandjoin( VipsImage **in, VipsImage *out, int n );
VIPS_DEPRECATED_FOR(vips_bandrank)
int im_rank_image( VipsImage **in, VipsImage *out, int n, int index );
VIPS_DEPRECATED_FOR(vips_bandrank)
int im_maxvalue( VipsImage **in, VipsImage *out, int n );
VIPS_DEPRECATED_FOR(vips_grid)
int im_grid( VipsImage *in, VipsImage *out, int tile_height, int across, int down );
VIPS_DEPRECATED_FOR(vips_scale)
int im_scale( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_scale)
int im_scaleps( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_msb)
int im_msb( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_msb)
int im_msb_band( VipsImage *in, VipsImage *out, int band );
VIPS_DEPRECATED_FOR(vips_zoom)
int im_zoom( VipsImage *in, VipsImage *out, int xfac, int yfac );
VIPS_DEPRECATED_FOR(vips_subsample)
int im_subsample( VipsImage *in, VipsImage *out, int xshrink, int yshrink );

VIPS_DEPRECATED_FOR(vips_gaussnoise)
int im_gaussnoise( VipsImage *out, int x, int y, double mean, double sigma );
VIPS_DEPRECATED_FOR(vips_text)
int im_text( VipsImage *out, const char *text, const char *font,
	int width, int alignment, int dpi );
VIPS_DEPRECATED_FOR(vips_black)
int im_black( VipsImage *out, int x, int y, int bands );
VIPS_DEPRECATED_FOR(vips_xyz)
int im_make_xy( VipsImage *out, const int xsize, const int ysize );
VIPS_DEPRECATED_FOR(vips_zone)
int im_zone( VipsImage *out, int size );
VIPS_DEPRECATED_FOR(vips_zone)
int im_fzone( VipsImage *out, int size );
VIPS_DEPRECATED_FOR(vips_eye)
int im_feye( VipsImage *out,
	const int xsize, const int ysize, const double factor );
VIPS_DEPRECATED_FOR(vips_eye)
int im_eye( VipsImage *out,
	const int xsize, const int ysize, const double factor );
VIPS_DEPRECATED_FOR(vips_grey)
int im_grey( VipsImage *out, const int xsize, const int ysize );
VIPS_DEPRECATED_FOR(vips_grey)
int im_fgrey( VipsImage *out, const int xsize, const int ysize );
VIPS_DEPRECATED_FOR(vips_sines)
int im_sines( VipsImage *out,
	int xsize, int ysize, double horfreq, double verfreq );
VIPS_DEPRECATED_FOR(vips_buildlut)
int im_buildlut( DOUBLEMASK *input, VipsImage *output );
VIPS_DEPRECATED_FOR(vips_invertlut)
int im_invertlut( DOUBLEMASK *input, VipsImage *output, int lut_size );
VIPS_DEPRECATED_FOR(vips_identity)
int im_identity( VipsImage *lut, int bands );
VIPS_DEPRECATED_FOR(vips_identity)
int im_identity_ushort( VipsImage *lut, int bands, int sz );

VIPS_DEPRECATED_FOR(vips_tonelut)
int im_tone_build_range( VipsImage *out,
	int in_max, int out_max,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );
VIPS_DEPRECATED_FOR(vips_tonelut)
int im_tone_build( VipsImage *out,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );

VIPS_DEPRECATED_FOR(vips_system)
int im_system( VipsImage *im, const char *cmd, char **out );
VIPS_DEPRECATED_FOR(vips_system)
VipsImage *im_system_image( VipsImage *im, 
	const char *in_format, const char *out_format, const char *cmd_format, 
	char **log );

VIPS_DEPRECATED_FOR(vips_complex)
int im_c2amph( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_complex)
int im_c2rect( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_imag)
int im_c2imag( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_real)
int im_c2real( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_complexform)
int im_ri2c( VipsImage *in1, VipsImage *in2, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_rot90)
int im_rot90( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_rot180)
int im_rot180( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_rot270)
int im_rot270( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_ifthenelse)
int im_ifthenelse( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_ifthenelse)
int im_blend( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );

VIPS_DEPRECATED
DOUBLEMASK *im_vips2mask( VipsImage *in, const char *filename );
VIPS_DEPRECATED
INTMASK *im_vips2imask( IMAGE *in, const char *filename );
VIPS_DEPRECATED
int im_mask2vips( DOUBLEMASK *in, VipsImage *out );
VIPS_DEPRECATED
int im_imask2vips( INTMASK *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_bandmean)
int im_bandmean( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_recomb)
int im_recomb( VipsImage *in, VipsImage *out, DOUBLEMASK *recomb );

VIPS_DEPRECATED
int im_argb2rgba( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_falsecolour)
int im_falsecolour( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_gamma)
int im_gammacorrect( VipsImage *in, VipsImage *out, double exponent );

VIPS_DEPRECATED_FOR(vips_tilecache)
int im_tile_cache_random( IMAGE *in, IMAGE *out,
	int tile_width, int tile_height, int max_tiles );

VIPS_DEPRECATED_FOR(vips_shrink)
int im_shrink( VipsImage *in, VipsImage *out, double xshrink, double yshrink );
VIPS_DEPRECATED_FOR(vips_affine)
int im_affinei( VipsImage *in, VipsImage *out, 
	VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh );
VIPS_DEPRECATED_FOR(vips_affine)
int im_affinei_all( VipsImage *in, VipsImage *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy );
VIPS_DEPRECATED_FOR(vips_shrink)
int im_rightshift_size( VipsImage *in, VipsImage *out, 
	int xshift, int yshift, int band_fmt );

VIPS_DEPRECATED_FOR(vips_Lab2XYZ)
int im_Lab2XYZ_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 );
VIPS_DEPRECATED_FOR(vips_Lab2XYZ)
int im_Lab2XYZ( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_XYZ2Lab)
int im_XYZ2Lab( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_XYZ2Lab)
int im_XYZ2Lab_temp( VipsImage *in, VipsImage *out, 
	double X0, double Y0, double Z0 );
VIPS_DEPRECATED_FOR(vips_Lab2LCh)
int im_Lab2LCh( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LCh2Lab)
int im_LCh2Lab( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LCh2CMC)
int im_LCh2UCS( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_CMC2LCh)
int im_UCS2LCh( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_XYZ2Yxy)
int im_XYZ2Yxy( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_Yxy2XYZ)
int im_Yxy2XYZ( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_float2rad)
int im_float2rad( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_rad2float)
int im_rad2float( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_Lab2LabQ)
int im_Lab2LabQ( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LabQ2Lab)
int im_LabQ2Lab( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_Lab2LabS)
int im_Lab2LabS( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LabS2Lab)
int im_LabS2Lab( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LabQ2LabS)
int im_LabQ2LabS( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LabS2LabQ)
int im_LabS2LabQ( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_LabQ2sRGB)
int im_LabQ2sRGB( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED
int im_XYZ2sRGB( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED
int im_sRGB2XYZ( IMAGE *in, IMAGE *out );

struct im_col_display;
#define im_col_displays(S) (NULL)
#define im_LabQ2disp_build_table(A, B) (NULL)
#define im_LabQ2disp_table(A, B, C) (im_LabQ2disp(A, B, C))

VIPS_DEPRECATED
int im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *disp );
VIPS_DEPRECATED
int im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *disp );

VIPS_DEPRECATED
int im_dE_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );
VIPS_DEPRECATED
int im_dECMC_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );

#define im_disp2XYZ(A, B, C) (im_sRGB2XYZ(A, B))
#define im_XYZ2disp(A, B, C) (im_XYZ2sRGB(A, B))
#define im_LabQ2disp(A, B, C) (im_LabQ2sRGB(A, B))

VIPS_DEPRECATED_FOR(vips_icc_transform)
int im_icc_transform( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	VipsIntent intent );

#define im_icc_present vips_icc_present

VIPS_DEPRECATED_FOR(vips_icc_import)
int im_icc_import( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename, VipsIntent intent );
VIPS_DEPRECATED_FOR(vips_icc_import)
int im_icc_import_embedded( VipsImage *in, VipsImage *out, VipsIntent intent );
VIPS_DEPRECATED_FOR(vips_icc_export)
int im_icc_export_depth( VipsImage *in, VipsImage *out, int depth,
	const char *output_profile_filename, VipsIntent intent );
VIPS_DEPRECATED_FOR(vips_icc_ac2rc)
int im_icc_ac2rc( VipsImage *in, VipsImage *out, const char *profile_filename );

VIPS_DEPRECATED
int im_LabQ2XYZ( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_UCS2XYZ( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_UCS2Lab( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_Lab2UCS( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_XYZ2UCS( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_dE76)
int im_dE_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_dECMC)
int im_dECMC_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED
int im_dE_fromXYZ( VipsImage *in1, VipsImage *in2, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_dE00)
int im_dE00_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );

VIPS_DEPRECATED
int im_lab_morph( VipsImage *in, VipsImage *out,
	DOUBLEMASK *mask,
	double L_offset, double L_scale,
	double a_scale, double b_scale );

#define im_col_dE00 vips_col_dE00

VIPS_DEPRECATED_FOR(vips_quadratic)
int im_quadratic( IMAGE *in, IMAGE *out, IMAGE *coeff );

VIPS_DEPRECATED_FOR(vips_maplut)
int im_maplut( VipsImage *in, VipsImage *out, VipsImage *lut );
VIPS_DEPRECATED
int im_hist( VipsImage *in, VipsImage *out, int bandno );
VIPS_DEPRECATED_FOR(vips_hist_find)
int im_histgr( VipsImage *in, VipsImage *out, int bandno );
VIPS_DEPRECATED_FOR(vips_hist_cum)
int im_histcum( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_hist_norm)
int im_histnorm( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_histeq( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_hist_equal)
int im_heq( VipsImage *in, VipsImage *out, int bandno );
VIPS_DEPRECATED_FOR(vips_hist_find_ndim)
int im_histnD( VipsImage *in, VipsImage *out, int bins );
VIPS_DEPRECATED_FOR(vips_hist_find_indexed)
int im_hist_indexed( VipsImage *index, VipsImage *value, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_hist_plot)
int im_histplot( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_project)
int im_project( VipsImage *in, VipsImage *hout, VipsImage *vout );
VIPS_DEPRECATED_FOR(vips_profile)
int im_profile( IMAGE *in, IMAGE *out, int dir );
VIPS_DEPRECATED
int im_hsp( VipsImage *in, VipsImage *ref, VipsImage *out );
VIPS_DEPRECATED
int im_histspec( VipsImage *in, VipsImage *ref, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_hist_local)
int im_lhisteq( VipsImage *in, VipsImage *out, int xwin, int ywin );
VIPS_DEPRECATED_FOR(vips_stdif)
int im_stdif( VipsImage *in, VipsImage *out,
	double a, double m0, double b, double s0, int xwin, int ywin );
VIPS_DEPRECATED_FOR(vips_percent)
int im_mpercent( VipsImage *in, double percent, int *out );
VIPS_DEPRECATED
int im_mpercent_hist( VipsImage *hist, double percent, int *out );
VIPS_DEPRECATED_FOR(vips_hist_ismonotonic)
int im_ismonotonic( VipsImage *lut, int *out );

VIPS_DEPRECATED
int im_tone_analyse( VipsImage *in, VipsImage *out,
	double Ps, double Pm, double Ph, double S, double M, double H );
VIPS_DEPRECATED
int im_tone_map( VipsImage *in, VipsImage *out, VipsImage *lut );

/* Not really correct, but who uses these.
 */
#define im_lhisteq_raw im_lhisteq
#define im_stdif_raw im_stdif

/* ruby-vips uses this
 */
#define vips_class_map_concrete_all vips_class_map_all

VIPS_DEPRECATED_FOR(vips_morph)
int im_dilate( VipsImage *in, VipsImage *out, INTMASK *mask );
VIPS_DEPRECATED_FOR(vips_morph)
int im_erode( VipsImage *in, VipsImage *out, INTMASK *mask );

VIPS_DEPRECATED_FOR(vips_conva)
int im_aconv( VipsImage *in, VipsImage *out, 
	DOUBLEMASK *mask, int n_layers, int cluster );
VIPS_DEPRECATED_FOR(vips_convi)
int im_conv( VipsImage *in, VipsImage *out, INTMASK *mask );
VIPS_DEPRECATED_FOR(vips_convf)
int im_conv_f( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );

VIPS_DEPRECATED_FOR(vips_convasep)
int im_aconvsep( VipsImage *in, VipsImage *out, 
	DOUBLEMASK *mask, int n_layers );

VIPS_DEPRECATED_FOR(vips_convsep)
int im_convsep( VipsImage *in, VipsImage *out, INTMASK *mask );
VIPS_DEPRECATED_FOR(vips_convsep)
int im_convsep_f( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );

VIPS_DEPRECATED_FOR(vips_compass)
int im_compass( VipsImage *in, VipsImage *out, INTMASK *mask );
VIPS_DEPRECATED_FOR(vips_compass)
int im_gradient( VipsImage *in, VipsImage *out, INTMASK *mask );
VIPS_DEPRECATED_FOR(vips_compass)
int im_lindetect( VipsImage *in, VipsImage *out, INTMASK *mask );

VIPS_DEPRECATED
int im_addgnoise( VipsImage *in, VipsImage *out, double sigma );

VIPS_DEPRECATED
int im_contrast_surface_raw( IMAGE *in, IMAGE *out, 
	int half_win_size, int spacing );
VIPS_DEPRECATED
int im_contrast_surface( VipsImage *in, VipsImage *out, 
	int half_win_size, int spacing );

VIPS_DEPRECATED
int im_grad_x( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_grad_y( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_fastcor)
int im_fastcor( VipsImage *in, VipsImage *ref, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_spcor)
int im_spcor( VipsImage *in, VipsImage *ref, VipsImage *out );
VIPS_DEPRECATED
int im_gradcor( VipsImage *in, VipsImage *ref, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_sharpen)
int im_sharpen( VipsImage *in, VipsImage *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 );

typedef enum {
        IM_MASK_IDEAL_HIGHPASS = 0,
        IM_MASK_IDEAL_LOWPASS = 1,
        IM_MASK_BUTTERWORTH_HIGHPASS = 2,
        IM_MASK_BUTTERWORTH_LOWPASS = 3,
        IM_MASK_GAUSS_HIGHPASS = 4,
        IM_MASK_GAUSS_LOWPASS = 5,

        IM_MASK_IDEAL_RINGPASS = 6,
        IM_MASK_IDEAL_RINGREJECT = 7,
        IM_MASK_BUTTERWORTH_RINGPASS = 8,
        IM_MASK_BUTTERWORTH_RINGREJECT = 9,
        IM_MASK_GAUSS_RINGPASS = 10,
        IM_MASK_GAUSS_RINGREJECT = 11,

        IM_MASK_IDEAL_BANDPASS = 12,
        IM_MASK_IDEAL_BANDREJECT = 13,
        IM_MASK_BUTTERWORTH_BANDPASS = 14,
        IM_MASK_BUTTERWORTH_BANDREJECT = 15,
        IM_MASK_GAUSS_BANDPASS = 16,
        IM_MASK_GAUSS_BANDREJECT = 17,

        IM_MASK_FRACTAL_FLT = 18
} ImMaskType;

/* We had them in the VIPS namespace for a while before deprecating them.
 */
#define VIPS_MASK_IDEAL_HIGHPASS IM_MASK_IDEAL_HIGHPASS 
#define VIPS_MASK_IDEAL_LOWPASS IM_MASK_IDEAL_LOWPASS 
#define VIPS_MASK_BUTTERWORTH_HIGHPASS IM_MASK_BUTTERWORTH_HIGHPASS 
#define VIPS_MASK_BUTTERWORTH_LOWPASS IM_MASK_BUTTERWORTH_LOWPASS 
#define VIPS_MASK_GAUSS_HIGHPASS IM_MASK_GAUSS_HIGHPASS 
#define VIPS_MASK_GAUSS_LOWPASS IM_MASK_GAUSS_LOWPASS 
#define VIPS_MASK_IDEAL_RINGPASS IM_MASK_IDEAL_RINGPASS 
#define VIPS_MASK_IDEAL_RINGREJECT IM_MASK_IDEAL_RINGREJECT 
#define VIPS_MASK_BUTTERWORTH_RINGPASS IM_MASK_BUTTERWORTH_RINGPASS 
#define VIPS_MASK_BUTTERWORTH_RINGREJECT IM_MASK_BUTTERWORTH_RINGREJECT 
#define VIPS_MASK_GAUSS_RINGPASS IM_MASK_GAUSS_RINGPASS 
#define VIPS_MASK_GAUSS_RINGREJECT IM_MASK_GAUSS_RINGREJECT 
#define VIPS_MASK_IDEAL_BANDPASS IM_MASK_IDEAL_BANDPASS 
#define VIPS_MASK_IDEAL_BANDREJECT IM_MASK_IDEAL_BANDREJECT 
#define VIPS_MASK_BUTTERWORTH_BANDPASS IM_MASK_BUTTERWORTH_BANDPASS 
#define VIPS_MASK_BUTTERWORTH_BANDREJECT IM_MASK_BUTTERWORTH_BANDREJECT 
#define VIPS_MASK_GAUSS_BANDPASS IM_MASK_GAUSS_BANDPASS 
#define VIPS_MASK_GAUSS_BANDREJECT IM_MASK_GAUSS_BANDREJECT 
#define VIPS_MASK_FRACTAL_FLT IM_MASK_FRACTAL_FLT 

#define VIPS_MASK IM_MASK

VIPS_DEPRECATED
int im_flt_image_freq( VipsImage *in, VipsImage *out, ImMaskType flag, ... );
VIPS_DEPRECATED
int im_create_fmask( VipsImage *out, 
	int xsize, int ysize, ImMaskType flag, ... );

VIPS_DEPRECATED_FOR(vips_fwfft)
int im_fwfft( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_invfft)
int im_invfft( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_invfft)
int im_invfftr( VipsImage *in, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_freqmult)
int im_freqflt( VipsImage *in, VipsImage *mask, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_spectrum)
int im_disp_ps( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED_FOR(vips_fractsurf)
int im_fractsurf( VipsImage *out, int size, double frd );
VIPS_DEPRECATED_FOR(vips_phasecor)
int im_phasecor_fft( VipsImage *in1, VipsImage *in2, VipsImage *out );

VIPS_DEPRECATED_FOR(vips_countlines)
int im_cntlines( VipsImage *im, double *nolines, int flag );
VIPS_DEPRECATED_FOR(vips_labelregions)
int im_label_regions( VipsImage *test, VipsImage *mask, int *segments );
VIPS_DEPRECATED_FOR(vips_rank)
int im_rank( VipsImage *in, VipsImage *out, int width, int height, int index );
VIPS_DEPRECATED
int im_zerox( VipsImage *in, VipsImage *out, int sign );

VIPS_DEPRECATED
int im_benchmarkn( VipsImage *in, VipsImage *out, int n );
VIPS_DEPRECATED
int im_benchmark2( VipsImage *in, double *out );

VIPS_DEPRECATED_FOR(vips_draw_circle)
int im_draw_circle( VipsImage *image, 
	int x, int y, int radius, gboolean fill, VipsPel *ink );

VIPS_DEPRECATED_FOR(vips_draw_mask)
int im_draw_mask( VipsImage *image, 
	VipsImage *mask_im, int x, int y, VipsPel *ink );
VIPS_DEPRECATED_FOR(vips_draw_image)
int im_draw_image( VipsImage *image, VipsImage *sub, int x, int y );
VIPS_DEPRECATED_FOR(vips_draw_rect)
int im_draw_rect( VipsImage *image, 
	int left, int top, int width, int height, int fill, VipsPel *ink );

typedef int (*VipsPlotFn)( VipsImage *image, int x, int y, 
	void *a, void *b, void *c ); 

VIPS_DEPRECATED_FOR(vips_draw_line)
int im_draw_line_user( VipsImage *image, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn plot, void *a, void *b, void *c );
VIPS_DEPRECATED_FOR(vips_draw_line)
int im_draw_line( VipsImage *image, 
	int x1, int y1, int x2, int y2, VipsPel *ink );
VIPS_DEPRECATED
int im_lineset( VipsImage *in, VipsImage *out, VipsImage *mask, VipsImage *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v );

VIPS_DEPRECATED
int im_insertset( VipsImage *main, VipsImage *sub, VipsImage *out, int n, int *x, int *y );

VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_draw_flood( VipsImage *image, int x, int y, VipsPel *ink, VipsRect *dout );
VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_draw_flood_blob( VipsImage *image, 
	int x, int y, VipsPel *ink, VipsRect *dout );
VIPS_DEPRECATED_FOR(vips_draw_flood1)
int im_draw_flood_other( VipsImage *image, VipsImage *test, 
	int x, int y, int serial, VipsRect *dout );

VIPS_DEPRECATED_FOR(vips_draw_point)
int im_draw_point( VipsImage *image, int x, int y, VipsPel *ink );
VIPS_DEPRECATED_FOR(vips_getpoint)
int im_read_point( VipsImage *image, int x, int y, VipsPel *ink );

VIPS_DEPRECATED_FOR(vips_draw_smudge)
int im_draw_smudge( VipsImage *image, 
	int left, int top, int width, int height );

VIPS_DEPRECATED
void im_filename_split( const char *path, char *name, char *mode );
VIPS_DEPRECATED_FOR(g_path_get_basename)
const char *im_skip_dir( const char *filename );
VIPS_DEPRECATED
void im_filename_suffix( const char *path, char *suffix );
VIPS_DEPRECATED
int im_filename_suffix_match( const char *path, const char *suffixes[] );
VIPS_DEPRECATED
char *im_getnextoption( char **in );
VIPS_DEPRECATED
char *im_getsuboption( const char *buf );

VIPS_DEPRECATED_FOR(vips_match)
int im_match_linear( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2 );
VIPS_DEPRECATED_FOR(vips_match)
int im_match_linear_search( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize );

VIPS_DEPRECATED_FOR(vips_globalbalance)
int im_global_balance( VipsImage *in, VipsImage *out, double gamma );
VIPS_DEPRECATED_FOR(vips_globalbalance)
int im_global_balancef( VipsImage *in, VipsImage *out, double gamma );

VIPS_DEPRECATED_FOR(vips_remosaic)
int im_remosaic( VipsImage *in, VipsImage *out,
	const char *old_str, const char *new_str );

VIPS_DEPRECATED_FOR(vips_merge)
int im_lrmerge( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int dx, int dy, int mwidth );
VIPS_DEPRECATED_FOR(vips_mosaic1)
int im_lrmerge1( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int mwidth );
VIPS_DEPRECATED_FOR(vips_merge)
int im_tbmerge( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int dx, int dy, int mwidth );
VIPS_DEPRECATED_FOR(vips_mosaic1)
int im_tbmerge1( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int mwidth );

VIPS_DEPRECATED_FOR(vips_mosaic)
int im_lrmosaic( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );
VIPS_DEPRECATED_FOR(vips_mosaic1)
int im_lrmosaic1( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );
VIPS_DEPRECATED_FOR(vips_mosaic)
int im_tbmosaic( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int bandno,
	int xref, int yref, int xsec, int ysec, 
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );
VIPS_DEPRECATED_FOR(vips_mosaic1)
int im_tbmosaic1( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth );

VIPS_DEPRECATED
int im_correl( VipsImage *ref, VipsImage *sec,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y );

VIPS_DEPRECATED
int im_align_bands( VipsImage *in, VipsImage *out );
VIPS_DEPRECATED
int im_maxpos_subpel( VipsImage *in, double *x, double *y );

VipsImage *vips__deprecated_open_read( const char *filename, gboolean sequential );
VipsImage *vips__deprecated_open_write( const char *filename );

void im__format_init( void );

/* Low-level read/write operations.
 */
VIPS_DEPRECATED
int im_jpeg2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_bufjpeg2vips( void *buf, size_t len, 
	VipsImage *out, gboolean header_only );
VIPS_DEPRECATED
int im_vips2jpeg( VipsImage *in, const char *filename );
VIPS_DEPRECATED
int im_vips2mimejpeg( VipsImage *in, int qfac );
VIPS_DEPRECATED
int im_vips2bufjpeg( VipsImage *in, VipsImage *out, 
	int qfac, char **obuf, int *olen );

VIPS_DEPRECATED
int im_tiff2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2tiff( VipsImage *in, const char *filename );
VIPS_DEPRECATED
int im_tile_cache( VipsImage *in, VipsImage *out, 
	int tile_width, int tile_height, int max_tiles );

VIPS_DEPRECATED
int im_magick2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_bufmagick2vips( void *buf, size_t len, 
	VipsImage *out, gboolean header_only );

VIPS_DEPRECATED
int im_exr2vips( const char *filename, VipsImage *out );

VIPS_DEPRECATED
int im_ppm2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2ppm( VipsImage *in, const char *filename );

VIPS_DEPRECATED
int im_analyze2vips( const char *filename, VipsImage *out );

VIPS_DEPRECATED
int im_csv2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2csv( VipsImage *in, const char *filename );

VIPS_DEPRECATED
int im_png2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2png( VipsImage *in, const char *filename );
VIPS_DEPRECATED
int im_vips2bufpng( VipsImage *in, VipsImage *out,
	int compression, int interlace, char **obuf, size_t *olen  );

VIPS_DEPRECATED
int im_webp2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2webp( VipsImage *in, const char *filename );

VIPS_DEPRECATED
int im_raw2vips( const char *filename, VipsImage *out,
	int width, int height, int bpp, int offset );
VIPS_DEPRECATED
int im_vips2raw( VipsImage *in, int fd );

VIPS_DEPRECATED
int im_mat2vips( const char *filename, VipsImage *out );

VIPS_DEPRECATED
int im_rad2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2rad( VipsImage *in, const char *filename );

VIPS_DEPRECATED
int im_fits2vips( const char *filename, VipsImage *out );
VIPS_DEPRECATED
int im_vips2fits( VipsImage *in, const char *filename );

VIPS_DEPRECATED
int im_vips2dz( VipsImage *in, const char *filename );

int im__bandup( const char *domain, VipsImage *in, VipsImage *out, int n );
int im__bandalike_vec( const char *domain, VipsImage **in, VipsImage **out, int n );
int im__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out1, VipsImage *out2 );
int im__formatalike_vec( VipsImage **in, VipsImage **out, int n );
int im__formatalike( VipsImage *in1, VipsImage *in2, VipsImage *out1, VipsImage *out2 );

int im__colour_unary( const char *domain,
	VipsImage *in, VipsImage *out, VipsInterpretation interpretation,
	im_wrapone_fn buffer_fn, void *a, void *b );
VipsImage **im__insert_base( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out );

/* TODO(kleisauke): These are also defined in pmosaicing.h */
int vips__find_lroverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );
int vips__find_tboverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );

/* A colour temperature.
 */
typedef struct {
	double X0, Y0, Z0;
} im_colour_temperature;

VIPS_DEPRECATED
void im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix );
VIPS_DEPRECATED
void im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask );


VIPS_DEPRECATED
int *im_ivector(int nl, int nh);
VIPS_DEPRECATED
float *im_fvector(int nl, int nh);
VIPS_DEPRECATED
double *im_dvector(int nl, int nh);
VIPS_DEPRECATED
void im_free_ivector(int *v, int nl, int nh);
VIPS_DEPRECATED
void im_free_fvector(float *v, int nl, int nh);
VIPS_DEPRECATED
void im_free_dvector(double *v, int nl, int nh);

VIPS_DEPRECATED
int **im_imat_alloc(int nrl, int nrh, int ncl, int nch);
VIPS_DEPRECATED
void im_free_imat(int **m, int nrl, int nrh, int ncl, int nch);
VIPS_DEPRECATED
float **im_fmat_alloc(int nrl, int nrh, int ncl, int nch);
VIPS_DEPRECATED
void im_free_fmat(float **m, int nrl, int nrh, int ncl, int nch);
VIPS_DEPRECATED
double **im_dmat_alloc(int nrl, int nrh, int ncl, int nch);
VIPS_DEPRECATED
void im_free_dmat(double **m, int nrl, int nrh, int ncl, int nch);

VIPS_DEPRECATED
int im_invmat( double **, int );

VIPS_DEPRECATED
int im_conv_f_raw( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );
VIPS_DEPRECATED
int im_convsep_f_raw( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );

VIPS_DEPRECATED
int im_greyc_mask( VipsImage *in, VipsImage *out, VipsImage *mask, 
	int iterations, float amplitude, float sharpness, float anisotropy, 
	float alpha, float sigma, float dl, float da, float gauss_prec, 
	int interpolation, int fast_approx );

VIPS_DEPRECATED
int vips_check_imask( const char *domain, INTMASK *mask );
VIPS_DEPRECATED
int vips_check_dmask( const char *domain, DOUBLEMASK *mask );
VIPS_DEPRECATED
int vips_check_dmask_1d( const char *domain, DOUBLEMASK *mask );

VIPS_DEPRECATED
GOptionGroup *vips_get_option_group( void );

/* old window manager API
 */
VIPS_DEPRECATED
VipsWindow *vips_window_ref( VipsImage *im, int top, int height );

VIPS_DEPRECATED
FILE *vips_popenf( const char *fmt, const char *mode, ... )
	__attribute__((format(printf, 1, 3)));

double *vips__ink_to_vector( const char *domain, 
	VipsImage *im, VipsPel *ink, int *n ); 

VipsPel *im__vector_to_ink( const char *domain, 
	VipsImage *im, int n, double *vec );

int vips__init( const char *argv0 );

size_t vips__get_sizeof_vipsobject( void );

/* This stuff is very, very old and should not be used by anyone now.
 */
#ifdef VIPS_ENABLE_ANCIENT
#include <vips/deprecated.h>
#endif /*VIPS_ENABLE_ANCIENT*/

#include <vips/dispatch.h>
#include <vips/almostdeprecated.h>

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VIPS7COMPAT_H*/


