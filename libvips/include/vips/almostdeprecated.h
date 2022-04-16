/* Old and broken stuff that we still enable by default, but don't document
 * and certainly don't recommend. 
 *
 * 30/6/09
 * 	- from vips.h
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

#ifndef IM_ALMOSTDEPRECATED_H
#define IM_ALMOSTDEPRECATED_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Was public, now deprecated.
 */
typedef enum {
	IM_BBITS_BYTE = 8,
	IM_BBITS_SHORT = 16,
	IM_BBITS_INT = 32,
	IM_BBITS_FLOAT = 32,
	IM_BBITS_COMPLEX = 64,
	IM_BBITS_DOUBLE = 64,
	IM_BBITS_DPCOMPLEX = 128
} VipsBBits;

/* Used to define a region of interest for im_extract() etc. Too boring to be
 * public API, see im_extract_area() etc.
 */
typedef struct { 
	int xstart;
	int ystart;
	int xsize;
	int ysize;
	int chsel;      /* 1 2 3 or 0, for r g b or all respectively
			 *(channel select)	*/
} IMAGE_BOX;

VIPS_DEPRECATED
int im_extract( IMAGE *, IMAGE *, IMAGE_BOX * );
VIPS_DEPRECATED
DOUBLEMASK *im_measure( IMAGE *im, IMAGE_BOX *box, int h, int v, 
	int *sel, int nsel, const char *name );

VIPS_DEPRECATED
gboolean im_isuint( IMAGE *im );
VIPS_DEPRECATED
gboolean im_isint( IMAGE *im );
VIPS_DEPRECATED
gboolean im_isfloat( IMAGE *im );
VIPS_DEPRECATED
gboolean im_isscalar( IMAGE *im );
VIPS_DEPRECATED
gboolean im_iscomplex( IMAGE *im );

VIPS_DEPRECATED
int im_c2ps( IMAGE *in, IMAGE *out );

VIPS_DEPRECATED
int im_clip( IMAGE *in, IMAGE *out );

#define MASK_IDEAL_HIGHPASS IM_MASK_IDEAL_HIGHPASS
#define MASK_IDEAL_LOWPASS IM_MASK_IDEAL_LOWPASS 
#define MASK_BUTTERWORTH_HIGHPASS IM_MASK_BUTTERWORTH_HIGHPASS 
#define MASK_BUTTERWORTH_LOWPASS IM_MASK_BUTTERWORTH_LOWPASS 
#define MASK_GAUSS_HIGHPASS IM_MASK_GAUSS_HIGHPASS 
#define MASK_GAUSS_LOWPASS IM_MASK_GAUSS_LOWPASS 

#define MASK_IDEAL_RINGPASS IM_MASK_IDEAL_RINGPASS
#define MASK_IDEAL_RINGREJECT IM_MASK_IDEAL_RINGREJECT 
#define MASK_BUTTERWORTH_RINGPASS IM_MASK_BUTTERWORTH_RINGPASS 
#define MASK_BUTTERWORTH_RINGREJECT IM_MASK_BUTTERWORTH_RINGREJECT 
#define MASK_GAUSS_RINGPASS IM_MASK_GAUSS_RINGPASS 
#define MASK_GAUSS_RINGREJECT IM_MASK_GAUSS_RINGREJECT 

#define MASK_IDEAL_BANDPASS IM_MASK_IDEAL_BANDPASS
#define MASK_IDEAL_BANDREJECT IM_MASK_IDEAL_BANDREJECT 
#define MASK_BUTTERWORTH_BANDPASS IM_MASK_BUTTERWORTH_BANDPASS 
#define MASK_BUTTERWORTH_BANDREJECT IM_MASK_BUTTERWORTH_BANDREJECT 
#define MASK_GAUSS_BANDPASS IM_MASK_GAUSS_BANDPASS 
#define MASK_GAUSS_BANDREJECT IM_MASK_GAUSS_BANDREJECT 

#define MASK_FRACTAL_FLT IM_MASK_FRACTAL_FLT

#define MaskType ImMaskType

/* Copy and swap types.
 */
typedef enum {
	IM_ARCH_NATIVE,
	IM_ARCH_BYTE_SWAPPED,
	IM_ARCH_LSB_FIRST,
	IM_ARCH_MSB_FIRST
} im_arch_type;

VIPS_DEPRECATED
gboolean im_isnative( im_arch_type arch );
VIPS_DEPRECATED
int im_copy_from( IMAGE *in, IMAGE *out, im_arch_type architecture );

/* Backwards compatibility macros.
 */
#define im_clear_error_string() im_error_clear()
#define im_errorstring() im_error_buffer()

/* Deprecated API.
 */
VIPS_DEPRECATED_FOR(vips_error)
void im_errormsg( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));
VIPS_DEPRECATED_FOR(vips_verror)
void im_verrormsg( const char *fmt, va_list ap );
VIPS_DEPRECATED_FOR(vips_error_system)
void im_errormsg_system( int err, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
VIPS_DEPRECATED_FOR(g_info)
void im_diagnostics( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));
VIPS_DEPRECATED_FOR(g_warning)
void im_warning( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));

VIPS_DEPRECATED
int im_iterate( VipsImage *im,
	VipsStartFn start, im_generate_fn generate, VipsStopFn stop,
	void *a, void *b
);

/* Async rendering.
 */
VIPS_DEPRECATED_FOR(vips_sink_screen)
int im_render_priority( VipsImage *in, VipsImage *out, VipsImage *mask,
	int width, int height, int max,
	int priority,
	void (*notify)( VipsImage *, VipsRect *, void * ), void *client );
VIPS_DEPRECATED_FOR(vips_sink_screen)
int im_cache( VipsImage *in, VipsImage *out, int width, int height, int max );

/* Deprecated operations.
 */
VIPS_DEPRECATED
int im_cmulnorm( IMAGE *in1, IMAGE *in2, IMAGE *out );
VIPS_DEPRECATED
int im_fav4( IMAGE **, IMAGE * );
VIPS_DEPRECATED
int im_gadd( double, IMAGE *, double, IMAGE *, double, IMAGE *);
VIPS_DEPRECATED
int im_litecor( IMAGE *, IMAGE *, IMAGE *, int, double );
VIPS_DEPRECATED_FOR(vips_sink_screen)
int im_render_fade( IMAGE *in, IMAGE *out, IMAGE *mask,
	int width, int height, int max,
	int fps, int steps,
	int priority,
	void (*notify)( IMAGE *, VipsRect *, void * ), void *client );
VIPS_DEPRECATED_FOR(vips_sink_screen)
int im_render( IMAGE *in, IMAGE *out, IMAGE *mask,
	int width, int height, int max,
	void (*notify)( IMAGE *, VipsRect *, void * ), void *client );

VIPS_DEPRECATED
int im_cooc_matrix( IMAGE *im, IMAGE *m,
	int xp, int yp, int xs, int ys, int dx, int dy, int flag );
VIPS_DEPRECATED
int im_cooc_asm( IMAGE *m, double *asmoment );
VIPS_DEPRECATED
int im_cooc_contrast( IMAGE *m, double *contrast );
VIPS_DEPRECATED
int im_cooc_correlation( IMAGE *m, double *correlation );
VIPS_DEPRECATED
int im_cooc_entropy( IMAGE *m, double *entropy );

VIPS_DEPRECATED
int im_glds_matrix( IMAGE *im, IMAGE *m,
	int xpos, int ypos, int xsize, int ysize, int dx, int dy );
VIPS_DEPRECATED
int im_glds_asm( IMAGE *m, double *asmoment );
VIPS_DEPRECATED
int im_glds_contrast( IMAGE *m, double *contrast );
VIPS_DEPRECATED
int im_glds_entropy( IMAGE *m, double *entropy );
VIPS_DEPRECATED
int im_glds_mean( IMAGE *m, double *mean );

VIPS_DEPRECATED
int im_dif_std(IMAGE *im, int xpos, int ypos, int xsize, int ysize, int dx, int dy, double *pmean, double *pstd);
VIPS_DEPRECATED
int im_simcontr( IMAGE *out, int xsize, int ysize );
VIPS_DEPRECATED
int im_spatres( IMAGE *in,  IMAGE *out, int step );

VIPS_DEPRECATED
int im_stretch3( IMAGE *in, IMAGE *out, double dx, double dy );

/* Renamed operations.
 */

/* arithmetic
 */
VIPS_DEPRECATED_FOR(vips_remainder_const)
int im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c );

/* boolean
 */
VIPS_DEPRECATED_FOR(vips_andimage_const1)
int im_andconst( IMAGE *, IMAGE *, double );
VIPS_DEPRECATED_FOR(vips_andimage_const)
int im_and_vec( IMAGE *, IMAGE *, int, double * );
VIPS_DEPRECATED_FOR(vips_orimage_const1)
int im_orconst( IMAGE *, IMAGE *, double );
VIPS_DEPRECATED_FOR(vips_orimage_const)
int im_or_vec( IMAGE *, IMAGE *, int, double * );
VIPS_DEPRECATED_FOR(vips_eorimage_const1)
int im_eorconst( IMAGE *, IMAGE *, double );
VIPS_DEPRECATED_FOR(vips_eorimage_const)
int im_eor_vec( IMAGE *, IMAGE *, int, double * );

/* mosaicing
 */
VIPS_DEPRECATED_FOR(vips_affine)
int im_affine( IMAGE *in, IMAGE *out,
	double a, double b, double c, double d, double dx, double dy,
	int ox, int oy, int ow, int oh );
VIPS_DEPRECATED_FOR(vips_similarity)
int im_similarity( IMAGE *in, IMAGE *out,
	double a, double b, double dx, double dy );
VIPS_DEPRECATED_FOR(vips_similarity)
int im_similarity_area( IMAGE *in, IMAGE *out,
	double a, double b, double dx, double dy,
	int ox, int oy, int ow, int oh );

/* colour
 */
VIPS_DEPRECATED_FOR(vips_icc_export)
int im_icc_export( IMAGE *in, IMAGE *out, 
	const char *output_profile_filename, int intent );

/* conversion
 */
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2dcm( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2cm( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2us( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2ui( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2s( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2i( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2d( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2f( IMAGE *in, IMAGE *out );
VIPS_DEPRECATED_FOR(vips_cast)
int im_clip2c( IMAGE *in, IMAGE *out );

VIPS_DEPRECATED
int im_slice( IMAGE *in, IMAGE *out, double, double );
VIPS_DEPRECATED
int im_thresh( IMAGE *in, IMAGE *out, double );

VIPS_DEPRECATED_FOR(printf)
int im_print( const char *message );

VIPS_DEPRECATED
int im_convsub( IMAGE *in, IMAGE *out, INTMASK *mask, int xskip, int yskip );

VIPS_DEPRECATED
int im_bernd( const char *tiffname, int x, int y, int w, int h );

VIPS_DEPRECATED
int im_resize_linear( IMAGE *, IMAGE *, int, int );

VIPS_DEPRECATED_FOR(vips_convf)
int im_convf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
VIPS_DEPRECATED_FOR(vips_convsep)
int im_convsepf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
VIPS_DEPRECATED
int im_conv_raw( IMAGE *in, IMAGE *out, INTMASK *mask );
VIPS_DEPRECATED
int im_convf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
VIPS_DEPRECATED
int im_convsep_raw( IMAGE *in, IMAGE *out, INTMASK *mask );
VIPS_DEPRECATED
int im_convsepf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
VIPS_DEPRECATED
int im_fastcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
VIPS_DEPRECATED
int im_spcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
VIPS_DEPRECATED
int im_gradcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
VIPS_DEPRECATED
int im_contrast_surface_raw( IMAGE *in, IMAGE *out, 
	int half_win_size, int spacing );

VIPS_DEPRECATED_FOR(vips_stdif)
int im_stdif_raw( IMAGE *in, IMAGE *out,
	double a, double m0, double b, double s0, int xwin, int ywin );
VIPS_DEPRECATED_FOR(vips_hist_local)
int im_lhisteq_raw( IMAGE *in, IMAGE *out, int xwin, int ywin );

VIPS_DEPRECATED_FOR(vips_morph)
int im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *m );
VIPS_DEPRECATED_FOR(vips_morph)
int im_dilate_raw( IMAGE *in, IMAGE *out, INTMASK *m );
VIPS_DEPRECATED
int im_rank_raw( IMAGE *in, IMAGE *out, int xsize, int ysize, int order );

/* inplace
 */
VIPS_DEPRECATED_FOR(vips_draw_circle)
int im_circle( IMAGE *im, int cx, int cy, int radius, int intensity );
VIPS_DEPRECATED_FOR(vips_draw_line1)
int im_line( IMAGE *, int, int, int, int, int );
VIPS_DEPRECATED_FOR(vips_labelregions)
int im_segment( IMAGE *test, IMAGE *mask, int *segments );
VIPS_DEPRECATED_FOR(vips_draw_rect)
int im_paintrect( IMAGE *im, VipsRect *r, PEL *ink );
VIPS_DEPRECATED_FOR(vips_draw_image)
int im_insertplace( IMAGE *main, IMAGE *sub, int x, int y );

VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink );
VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood_blob_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink );
VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood_other_copy( IMAGE *test, IMAGE *mark, IMAGE *out, 
	int x, int y, int serial );

VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood( IMAGE *im, int x, int y, PEL *ink, VipsRect *dout );
VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood_blob( IMAGE *im, int x, int y, PEL *ink, VipsRect *dout );
VIPS_DEPRECATED_FOR(vips_draw_flood)
int im_flood_other( IMAGE *test, IMAGE *mark, 
	int x, int y, int serial, VipsRect *dout );

VIPS_DEPRECATED_FOR(vips_draw_line)
int im_fastline( IMAGE *im, int x1, int y1, int x2, int y2, PEL *pel );
VIPS_DEPRECATED_FOR(vips_draw_line)
int im_fastlineuser( IMAGE *im, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn fn, void *client1, void *client2, void *client3 );

VIPS_DEPRECATED_FOR(vips_draw_mask)
int im_plotmask( IMAGE *im, int ix, int iy, PEL *ink, PEL *mask, VipsRect *r );
VIPS_DEPRECATED_FOR(vips_getpoint)
int im_readpoint( IMAGE *im, int x, int y, PEL *pel );
VIPS_DEPRECATED_FOR(vips_draw_point)
int im_plotpoint( IMAGE *im, int x, int y, PEL *pel );

VIPS_DEPRECATED_FOR(vips_draw_smudge)
int im_smudge( IMAGE *image, int ix, int iy, VipsRect *r );
VIPS_DEPRECATED
int im_smear( IMAGE *im, int ix, int iy, VipsRect *r );

VIPS_DEPRECATED_FOR(g_warning)
void vips_warn( const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
VIPS_DEPRECATED_FOR(g_warning)
void vips_vwarn( const char *domain, const char *fmt, va_list ap );
VIPS_DEPRECATED
void vips_info_set( gboolean info );
VIPS_DEPRECATED_FOR(g_info)
void vips_info( const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
VIPS_DEPRECATED_FOR(g_info)
void vips_vinfo( const char *domain, const char *fmt, va_list ap );

VIPS_DEPRECATED_FOR(vips_autorot)
VipsAngle vips_autorot_get_angle( VipsImage *image );

/* iofuncs
 */
VIPS_DEPRECATED_FOR(g_free)
int vips_free( void *buf );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_ALMOSTDEPRECATED_H*/
