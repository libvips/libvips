/* Old and broken stuff we do not enable by default
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_DEPRECATED_H
#define IM_DEPRECATED_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* On win32, need to override the wingdi defs for these. Yuk!
 */
#ifdef HAVE_WINDOWS_H
#ifdef RGB
#undef RGB
#endif
#ifdef CMYK
#undef CMYK
#endif
#endif /*HAVE_WINDOWS_H*/

/* Bits per Band */
#define BBBYTE		8
#define BBSHORT		16
#define BBINT		32
#define BBFLOAT		32
#define BBCOMPLEX	64	/* complex consisting of two floats */
#define BBDOUBLE	64
#define BBDPCOMPLEX	128	/* complex consisting of two doubles */

/* picture Type */
#define MULTIBAND	0
#define B_W		1
#define LUMINACE	2
#define XRAY		3
#define IR		4
#define YUV		5
#define RED_ONLY	6			/* red channel only	*/
#define GREEN_ONLY	7			/* green channel only	*/
#define BLUE_ONLY	8			/* blue channel only	*/
#define POWER_SPECTRUM	9
#define HISTOGRAM	10
#define FOURIER		24

/* Colour spaces.
 */
#define LUT		11
#define XYZ		12
#define LAB		13
#define CMC		14
#define CMYK		15
#define LABQ		16
#define RGB		17
#define UCS		18
#define LCH		19
#define LABS		21
#define sRGB		22
#define YXY		23

/* BandFmt 
 */
#define FMTNOTSET	-1	
#define FMTUCHAR	0	/* pels interpreted as unsigned chars */
#define FMTCHAR		1	/* pels interpreted as signed chars */
#define FMTUSHORT	2	/* pels interpreted as unsigned shorts */
#define FMTSHORT	3	/* pels interpreted as signed shorts */
#define FMTUINT		4	/* pels interpreted as unsigned ints */
#define FMTINT		5	/* pels interpreted as signed ints */
#define FMTFLOAT	6	/* pels interpreted as floats */
#define FMTCOMPLEX	7	/* pels interpreted as complex (2 float each) */
#define FMTDOUBLE	8	/* pels interpreted as unsigned double */
#define FMTDPCOMPLEX	9	/* pels interpreted as complex (2 double each)*/

/* Coding type 
 */
#define NOCODING		0
#define COLQUANT		1
#define LABPACK			2
#define LABPACK_COMPRESSED	3
#define RGB_COMPRESSED		4
#define LUM_COMPRESSED		5

/* Compression type 
 */
#define NO_COMPRESSION		0
#define TCSF_COMPRESSION	1
#define JPEG_COMPRESSION	2

#define esize(I) IM_IMAGE_SIZEOF_ELEMENT(I)
#define psize(I) IM_IMAGE_SIZEOF_PEL(I)
#define lsize(I) IM_IMAGE_SIZEOF_LINE(I)
#define niele(I) IM_IMAGE_N_ELEMENTS(I)

#define lskip(B) IM_REGION_LSKIP(B)
#define nele(B) IM_REGION_N_ELEMENTS(B)
#define rsize(B) IM_REGION_SIZEOF_LINE(B)

#define addr(B,X,Y) IM_REGION_ADDR(B,X,Y) 

#ifndef MAX
#define MAX(A,B) IM_MAX(A, B)
#define MIN(A,B) IM_MIN(A, B)
#endif /*MAX*/

#define CLIP(A,V,B) IM_CLIP(A, V, B)
#define NEW(IM,A) IM_NEW(IM,A)
#define NUMBER(R) IM_NUMBER(R)
#define ARRAY(IM,N,T) IM_ARRAY(IM,N,T)

#define UNROLL( N, OPER ) IM_UNROLL( N, OPER )
#define RINT( R ) IM_RINT( R )

#define CLIP_UCHAR( V, SEQ ) IM_CLIP_UCHAR( V, SEQ )
#define CLIP_USHORT( V, SEQ ) IM_CLIP_USHORT( V, SEQ )
#define CLIP_CHAR( V, SEQ ) IM_CLIP_CHAR( V, SEQ )
#define CLIP_SHORT( V, SEQ ) IM_CLIP_SHORT( V, SEQ )
#define CLIP_NONE( V, SEQ ) IM_CLIP_NONE( V, SEQ )

#define right(R) IM_RECT_RIGHT(R)
#define bottom(R) IM_RECT_BOTTOM(R)

/* Backwards compatibility macros.
 */
#define im_clear_error_string() im_error_clear()
#define im_errorstring() im_error_buffer()

/* Deprecated API.
 */
void im_errormsg( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));
void im_verrormsg( const char *fmt, va_list ap );
void im_errormsg_system( int err, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
void im_diagnostics( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));
void im_warning( const char *fmt, ... )
	__attribute__((format(printf, 1, 2)));

/* Deprecated operations.
 */
int im_cmulnorm( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_fav4( IMAGE **, IMAGE * );
int im_gadd( double, IMAGE *, double, IMAGE *, double, IMAGE *);
int im_litecor( IMAGE *, IMAGE *, IMAGE *, int, double );
int im_render_fade( IMAGE *in, IMAGE *out, IMAGE *mask,
	int width, int height, int max,
	int fps, int steps,
	int priority,
	void (*notify)( IMAGE *, Rect *, void * ), void *client );
int im_render( IMAGE *in, IMAGE *out, IMAGE *mask,
	int width, int height, int max,
	void (*notify)( IMAGE *, Rect *, void * ), void *client );

/* Renamed operations.
 */

/* arithmetic
 */
int im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c );

/* boolean
 */
int im_andconst( IMAGE *, IMAGE *, double );
int im_and_vec( IMAGE *, IMAGE *, int, double * );
int im_orconst( IMAGE *, IMAGE *, double );
int im_or_vec( IMAGE *, IMAGE *, int, double * );
int im_eorconst( IMAGE *, IMAGE *, double );
int im_eor_vec( IMAGE *, IMAGE *, int, double * );

/* mosaicing
 */
int im_affine( IMAGE *in, IMAGE *out,
	double a, double b, double c, double d, double dx, double dy,
	int ox, int oy, int ow, int oh );
int im_similarity( IMAGE *in, IMAGE *out,
	double a, double b, double dx, double dy );
int im_similarity_area( IMAGE *in, IMAGE *out,
	double a, double b, double dx, double dy,
	int ox, int oy, int ow, int oh );

/* colour
 */
int im_icc_export( IMAGE *in, IMAGE *out, 
	const char *output_profile_filename, VipsIntent intent );

/* conversion
 */
int im_clip2dcm( IMAGE *in, IMAGE *out );
int im_clip2cm( IMAGE *in, IMAGE *out );
int im_clip2us( IMAGE *in, IMAGE *out );
int im_clip2ui( IMAGE *in, IMAGE *out );
int im_clip2s( IMAGE *in, IMAGE *out );
int im_clip2i( IMAGE *in, IMAGE *out );
int im_clip2d( IMAGE *in, IMAGE *out );
int im_clip2f( IMAGE *in, IMAGE *out );
int im_clip2c( IMAGE *in, IMAGE *out );

int im_slice( IMAGE *in, IMAGE *out, double, double );
int im_thresh( IMAGE *in, IMAGE *out, double );

int im_print( const char *message );

int im_convsub( IMAGE *in, IMAGE *out, INTMASK *mask, int xskip, int yskip );

int im_bernd( const char *tiffname, int x, int y, int w, int h );

int im_resize_linear( IMAGE *, IMAGE *, int, int );

int im_line( IMAGE *, int, int, int, int, int );
int im_segment( IMAGE *test, IMAGE *mask, int *segments );

int im_convf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_convsepf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_conv_raw( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_convf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_convsep_raw( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_convsepf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_fastcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_spcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_gradcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_contrast_surface_raw( IMAGE *in, IMAGE *out, 
	int half_win_size, int spacing );

int im_stdif_raw( IMAGE *in, IMAGE *out,
	double a, double m0, double b, double s0, int xwin, int ywin );
int im_lhisteq_raw( IMAGE *in, IMAGE *out, int xwin, int ywin );

int im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *m );
int im_dilate_raw( IMAGE *in, IMAGE *out, INTMASK *m );
int im_rank_raw( IMAGE *in, IMAGE *out, int xsize, int ysize, int order );

gboolean im_isuint( IMAGE *im );
gboolean im_isint( IMAGE *im );
gboolean im_isfloat( IMAGE *im );
gboolean im_isscalar( IMAGE *im );
gboolean im_iscomplex( IMAGE *im );

int im_c2ps( IMAGE *in, IMAGE *out );

int im_clip( IMAGE *in, IMAGE *out );

/* Copy and swap types.
 */
typedef enum {
	IM_ARCH_NATIVE,
	IM_ARCH_BYTE_SWAPPED,
	IM_ARCH_LSB_FIRST,
	IM_ARCH_MSB_FIRST
} im_arch_type;

gboolean im_isnative( im_arch_type arch );
int im_copy_from( IMAGE *in, IMAGE *out, im_arch_type architecture );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_DEPRECATED_H*/
