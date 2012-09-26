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

#define im_col_L2Lucs vips_col_L2Lucs
#define im_col_C2Cucs vips_col_C2Cucs
#define im_col_Ch2hucs vips_col_Ch2hucs

#define im_col_make_tables_UCS vips_col_make_tables_UCS
#define im_col_Lucs2L vips_col_Lucs2L
#define im_col_Cucs2C vips_col_Cucs2C
#define im_col_Chucs2h vips_col_Chucs2h

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
#define im_image vips_image_new_from_memory
#define im_binfile vips_image_new_from_file_raw
#define im__open_temp vips_image_new_disc_temp
#define im__test_kill( I ) (vips_image_get_kill( I ))
#define im__start_eval( I ) (vips_image_preeval( I ), vips_image_get_kill( I ))
#define im__handle_eval( I, W, H ) \
	(vips_image_eval( I, W, H ), vips_image_get_kill( I ))
#define im__end_eval vips_image_posteval
#define im_invalidate vips_image_invalidate_all
#define im_isfile vips_image_isfile
#define im_printdesc( I ) vips_object_print_dump( VIPS_OBJECT( I ) )
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

VipsImage *im_open( const char *filename, const char *mode );

VipsImage *im_open_local( VipsImage *parent, 
	const char *filename, const char *mode );
int im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n, const char *filename, const char *mode );

#define im_callback_fn VipsCallbackFn

int im_add_callback( VipsImage *im, 
	const char *callback, im_callback_fn fn, void *a, void *b );
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

int im_demand_hint (IMAGE * im, VipsDemandStyle hint, ...);
#define im_demand_hint_array( A, B, C ) (vips_demand_hint_array( A, B, C ), 0)

#define im_start_one vips_start_one
#define im_stop_one vips_stop_one
#define im_start_many vips_start_many
#define im_stop_many vips_stop_many
#define im_allocate_input_array vips_allocate_input_array
#define im_start_fn VipsStartFn
typedef int (*im_generate_fn)( VipsRegion *out, void *seq, void *a, void *b );
#define im_stop_fn VipsStopFn
int im_generate( VipsImage *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b );

#define im__mmap vips__mmap
#define im__munmap vips__munmap
#define im_mapfile vips_mapfile
#define im_mapfilerw vips_mapfilerw
#define im_remapfilerw vips_remapfilerw

#define im__print_renders vips__print_renders

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

int vips_check_coding_labq( const char *domain, VipsImage *im );
int vips_check_coding_rad( const char *domain, VipsImage *im );
int vips_check_bands_3ormore( const char *domain, VipsImage *im );

/* Buffer processing.
 */
typedef void (*im_wrapone_fn)( void *in, void *out, int width,
	void *a, void *b );
int im_wrapone( VipsImage *in, VipsImage *out,
	im_wrapone_fn fn, void *a, void *b );

typedef void (*im_wraptwo_fn)( void *in1, void *in2, void *out, 
        int width, void *a, void *b );
int im_wraptwo( VipsImage *in1, VipsImage *in2, VipsImage *out,
	im_wraptwo_fn fn, void *a, void *b );

typedef void (*im_wrapmany_fn)( void **in, void *out, int width,
	void *a, void *b );
int im_wrapmany( VipsImage **in, VipsImage *out,
	im_wrapmany_fn fn, void *a, void *b );

#define IM_META_EXIF_NAME VIPS_META_EXIF_NAME 
#define IM_META_ICC_NAME VIPS_META_ICC_NAME 
#define IM_META_XML VIPS_META_XML 
#define IM_META_RESOLUTION_UNIT VIPS_META_RESOLUTION_UNIT 
#define IM_TYPE_SAVE_STRING VIPS_TYPE_SAVE_STRING 
#define IM_TYPE_BLOB VIPS_TYPE_BLOB 
#define IM_TYPE_AREA VIPS_TYPE_AREA 
#define IM_TYPE_REF_STRING VIPS_TYPE_REF_STRING 

#define im_header_map_fn VipsImageMapFn
#define im_header_map vips_image_map

#define im_header_int vips_image_get_int
#define im_header_double vips_image_get_double
#define im_header_string vips_image_get_string
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
#define im_filename_split vips_filename_split
#define im_skip_dir vips_skip_dir
#define im_filename_suffix vips_filename_suffix
#define im_filename_suffix_match vips_filename_suffix_match
#define im_getnextoption vips_getnextoption
#define im_getsuboption vips_getsuboption
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

#define IM_EXEEXT VIPS_EXEEXT

#define IM_SIZEOF_HEADER VIPS_SIZEOF_HEADER

#define im_concurrency_set vips_concurrency_set
#define im_concurrency_get vips_concurrency_get

int im_add( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_subtract( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_multiply( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_divide( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_min( VipsImage *in, double *out );
int im_minpos( VipsImage *in, int *xpos, int *ypos, double *out );
int im_max( VipsImage *in, double *out );
int im_maxpos( VipsImage *in, int *xpos, int *ypos, double *out );
int im_avg( VipsImage *in, double *out );
int im_deviate( VipsImage *in, double *out );
int im_invert( VipsImage *in, VipsImage *out );
int im_lintra( double a, VipsImage *in, double b, VipsImage *out );
int im_lintra_vec( int n, double *a, VipsImage *in, double *b, VipsImage *out );
int im_abs( VipsImage *in, VipsImage *out );
int im_sign( VipsImage *in, VipsImage *out );
DOUBLEMASK *im_stats( VipsImage *in );
DOUBLEMASK *im_measure_area( VipsImage *im, 
	int left, int top, int width, int height, 
	int h, int v, 
	int *sel, int nsel, const char *name );

int im_sintra( VipsImage *in, VipsImage *out );
int im_costra( VipsImage *in, VipsImage *out );
int im_tantra( VipsImage *in, VipsImage *out );
int im_asintra( VipsImage *in, VipsImage *out );
int im_acostra( VipsImage *in, VipsImage *out );
int im_atantra( VipsImage *in, VipsImage *out );
int im_logtra( VipsImage *in, VipsImage *out );
int im_log10tra( VipsImage *in, VipsImage *out );
int im_exptra( VipsImage *in, VipsImage *out );
int im_exp10tra( VipsImage *in, VipsImage *out );

int im_floor( VipsImage *in, VipsImage *out );
int im_rint( VipsImage *in, VipsImage *out );
int im_ceil( VipsImage *in, VipsImage *out );

int im_equal( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_notequal( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_less( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_lesseq( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_more( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_moreeq( VipsImage *in1, VipsImage *in2, VipsImage *out );

int im_andimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_orimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_eorimage( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_andimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_orimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_eorimage_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_andimageconst( VipsImage *in, VipsImage *out, double c );
int im_orimageconst( VipsImage *in, VipsImage *out, double c );
int im_eorimageconst( VipsImage *in, VipsImage *out, double c );

int im_shiftleft_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_shiftleft( VipsImage *in, VipsImage *out, int n );
int im_shiftright_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_shiftright( VipsImage *in, VipsImage *out, int n );

int im_remainder( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_remainder_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_remainderconst( VipsImage *in, VipsImage *out, double c );

int im_powtra( VipsImage *in, VipsImage *out, double e );
int im_powtra_vec( VipsImage *in, VipsImage *out, int n, double *e );
int im_expntra( VipsImage *in, VipsImage *out, double e );
int im_expntra_vec( VipsImage *in, VipsImage *out, int n, double *e );

int im_equal_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_notequal_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_less_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_lesseq_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_more_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_moreeq_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_equalconst( VipsImage *in, VipsImage *out, double c );
int im_notequalconst( VipsImage *in, VipsImage *out, double c );
int im_lessconst( VipsImage *in, VipsImage *out, double c );
int im_lesseqconst( VipsImage *in, VipsImage *out, double c );
int im_moreconst( VipsImage *in, VipsImage *out, double c );
int im_moreeqconst( VipsImage *in, VipsImage *out, double c );

int im_copy( VipsImage *in, VipsImage *out );
int im_copy_set( VipsImage *in, VipsImage *out, 
	VipsInterpretation interpretation, 
	float xres, float yres, int xoffset, int yoffset );
int im_copy_set_meta( VipsImage *in, VipsImage *out, 
	const char *field, GValue *value );
int im_copy_morph( VipsImage *in, VipsImage *out, 
	int bands, VipsBandFormat format, VipsCoding coding );
int im_copy_swap( VipsImage *in, VipsImage *out );
int im_copy_native( VipsImage *in, VipsImage *out, gboolean is_msb_first );
int im_embed( VipsImage *in, VipsImage *out, 
	int type, int x, int y, int width, int height );
int im_fliphor( VipsImage *in, VipsImage *out );
int im_flipver( VipsImage *in, VipsImage *out );
int im_insert( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
int im_insert_noexpand( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
int im_lrjoin( VipsImage *left, VipsImage *right, VipsImage *out );
int im_tbjoin( VipsImage *top, VipsImage *bottom, VipsImage *out );
int im_extract_area( VipsImage *in, VipsImage *out, 
	int left, int top, int width, int height );
int im_extract_band( VipsImage *in, VipsImage *out, int band );
int im_extract_bands( VipsImage *in, VipsImage *out, int band, int nbands );
int im_extract_areabands( VipsImage *in, VipsImage *out,
	int left, int top, int width, int height, int band, int nbands );
int im_replicate( VipsImage *in, VipsImage *out, int across, int down );
int im_clip2fmt( VipsImage *in, VipsImage *out, VipsBandFormat fmt );
int im_bandjoin( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_gbandjoin( VipsImage **in, VipsImage *out, int n );
int im_black( VipsImage *out, int x, int y, int bands );

int im_c2amph( VipsImage *in, VipsImage *out );
int im_c2rect( VipsImage *in, VipsImage *out );
int im_c2imag( VipsImage *in, VipsImage *out );
int im_c2real( VipsImage *in, VipsImage *out );
int im_ri2c( VipsImage *in1, VipsImage *in2, VipsImage *out );

int im_rot90( VipsImage *in, VipsImage *out );
int im_rot180( VipsImage *in, VipsImage *out );
int im_rot270( VipsImage *in, VipsImage *out );

int im_ifthenelse( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );
int im_blend( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );

DOUBLEMASK *im_vips2mask( VipsImage *in, const char *filename );
int im_mask2vips( DOUBLEMASK *in, VipsImage *out );

int im_bandmean( VipsImage *in, VipsImage *out );
int im_recomb( VipsImage *in, VipsImage *out, DOUBLEMASK *recomb );

int im_argb2rgba( VipsImage *in, VipsImage *out );

int im_shrink( VipsImage *in, VipsImage *out, double xshrink, double yshrink );

int im_Lab2XYZ_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 );
int im_Lab2XYZ( IMAGE *in, IMAGE *out );
int im_XYZ2Lab( VipsImage *in, VipsImage *out );
int im_XYZ2Lab_temp( VipsImage *in, VipsImage *out, 
	double X0, double Y0, double Z0 );
int im_Lab2LCh( VipsImage *in, VipsImage *out );
int im_LCh2Lab( VipsImage *in, VipsImage *out );
int im_LCh2UCS( VipsImage *in, VipsImage *out );
int im_UCS2LCh( VipsImage *in, VipsImage *out );
int im_XYZ2Yxy( VipsImage *in, VipsImage *out );
int im_Yxy2XYZ( VipsImage *in, VipsImage *out );
int im_float2rad( VipsImage *in, VipsImage *out );
int im_rad2float( VipsImage *in, VipsImage *out );
int im_Lab2LabQ( VipsImage *in, VipsImage *out );
int im_LabQ2Lab( VipsImage *in, VipsImage *out );
int im_Lab2LabS( VipsImage *in, VipsImage *out );
int im_LabS2Lab( VipsImage *in, VipsImage *out );
int im_LabQ2LabS( VipsImage *in, VipsImage *out );
int im_LabS2LabQ( VipsImage *in, VipsImage *out );
int im_LabQ2sRGB( VipsImage *in, VipsImage *out );

int im_XYZ2sRGB( IMAGE *in, IMAGE *out );
int im_sRGB2XYZ( IMAGE *in, IMAGE *out );

struct im_col_display;
#define im_col_displays(S) (NULL)
#define im_LabQ2disp_build_table(A, B) (NULL)
#define im_LabQ2disp_table(A, B, C) (im_LabQ2disp(A, B, C))

int im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *disp );
int im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *disp );

int im_dE_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );
int im_dECMC_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );

#define im_disp2XYZ(A, B, C) (im_sRGB2XYZ(A, B))
#define im_XYZ2disp(A, B, C) (im_XYZ2sRGB(A, B))
#define im_LabQ2disp(A, B, C) (im_LabQ2sRGB(A, B))

int im_icc_transform( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	VipsIntent intent );

#define im_icc_present vips_icc_present

int im_icc_import( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename, VipsIntent intent );
int im_icc_import_embedded( VipsImage *in, VipsImage *out, VipsIntent intent );
int im_icc_export_depth( VipsImage *in, VipsImage *out, int depth,
	const char *output_profile_filename, VipsIntent intent );
int im_icc_ac2rc( VipsImage *in, VipsImage *out, const char *profile_filename );

/* ruby-vips uses this
 */
#define vips_class_map_concrete_all vips_class_map_all

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_VIPS7COMPAT_H*/


