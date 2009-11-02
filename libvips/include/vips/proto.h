/* @(#) Header file for Birkbeck/VIPS Image Processing Library
 * Authors: N. Dessipris, K. Martinez, Birkbeck College, London.
 * and J. Cupitt The National Gallery, London.
 *
 * Sept 94
 *
 * 15/7/96 JC
 * 	- now does C++ extern stuff
 *	- many more protos
 * 15/4/97 JC
 *	- protos split out here, more of them
 *	- still not complete tho' ...
 * 8/4/99 JC
 *	- lots of consts added to please C++
 *	- and more protos added
 * 11/9/06
 * 	- internal protos cut out to help SWIG
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

#ifndef IM_PROTO_H
#define IM_PROTO_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Need these for some protos.
 */
#include <stdarg.h>
#include <sys/types.h>
#include <glib-object.h>

/* If we're being parsed by SWIG, remove gcc attributes.
 */
#ifdef SWIG
#  ifndef __attribute__
#    define __attribute__(x)  /*NOTHING*/
#  endif
#endif /*SWIG*/

/* morphology
 */
int im_dilate( IMAGE *in, IMAGE *out, INTMASK *m );
int im_dilate_raw( IMAGE *in, IMAGE *out, INTMASK *m );
int im_erode( IMAGE *in, IMAGE *out, INTMASK *m );
int im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *m );
int im_cntlines( IMAGE *im, double *nolines, int flag );
int im_profile( IMAGE *in, IMAGE *out, int dir );

/* convolution
 */
void im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix );
void im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask );
INTMASK *im_create_imask( const char *, int, int );
INTMASK *im_create_imaskv( const char *, int, int, ... );
DOUBLEMASK *im_create_dmask( const char *, int, int );
DOUBLEMASK *im_create_dmaskv( const char *, int, int, ... );
INTMASK *im_dup_imask( INTMASK *, const char * );
DOUBLEMASK *im_dup_dmask( DOUBLEMASK *, const char * );
int im_free_imask( INTMASK * );
int im_free_dmask( DOUBLEMASK * );
INTMASK *im_read_imask( const char * );
DOUBLEMASK *im_read_dmask( const char * );
void im_print_imask( INTMASK * );
void im_print_dmask( DOUBLEMASK * );
int im_write_imask( INTMASK * );
int im_write_dmask( DOUBLEMASK * );
int im_write_imask_name( INTMASK *, const char * );
int im_write_dmask_name( DOUBLEMASK *, const char * );
INTMASK *im_scale_dmask( DOUBLEMASK *, const char * );
void im_norm_dmask( DOUBLEMASK *mask );
int *im_offsets45( int );
int *im_offsets90( int );
INTMASK *im_rotate_imask90( INTMASK *, const char * );
INTMASK *im_rotate_imask45( INTMASK *, const char * );
DOUBLEMASK *im_rotate_dmask90( DOUBLEMASK *, const char * );
DOUBLEMASK *im_rotate_dmask45( DOUBLEMASK *, const char * );
INTMASK *im_log_imask( const char *, double, double );
DOUBLEMASK *im_log_dmask( const char *, double, double );
INTMASK *im_gauss_imask( const char *, double, double );
INTMASK *im_gauss_imask_sep( const char *, double, double );
DOUBLEMASK *im_gauss_dmask( const char *, double, double );

int im_rank( IMAGE *, IMAGE *, int, int, int );
int im_sharpen( IMAGE *, IMAGE *, int, double, double, double, double, double );
int im_addgnoise( IMAGE *, IMAGE *, double );
int im_gaussnoise( IMAGE *, int, int, double, double );

int im_zerox( IMAGE *, IMAGE *, int );

int im_maxvalue( IMAGE **in, IMAGE *out, int n );
int im_rank_image( IMAGE **in, IMAGE *out, int n, int index );
int im_compass( IMAGE *, IMAGE *, INTMASK * );
int im_gradient( IMAGE *, IMAGE *, INTMASK * );
int im_lindetect( IMAGE *, IMAGE *, INTMASK * );
int im_conv( IMAGE *, IMAGE *, INTMASK * );
int im_conv_raw( IMAGE *, IMAGE *, INTMASK * );
int im_convf( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convf_raw( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsep( IMAGE *, IMAGE *, INTMASK * );
int im_convsep_raw( IMAGE *, IMAGE *, INTMASK * );
int im_convsepf( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsepf_raw( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsub( IMAGE *, IMAGE *, INTMASK *, int, int );

int im_grad_x( IMAGE *in, IMAGE *out );
int im_grad_y( IMAGE *in, IMAGE *out );

int im_phasecor_fft( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_fastcor( IMAGE *, IMAGE *, IMAGE * );
int im_fastcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_spcor( IMAGE *, IMAGE *, IMAGE * );
int im_spcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_gradcor( IMAGE *, IMAGE *, IMAGE * );
int im_gradcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_contrast_surface( IMAGE *, IMAGE *, int, int );
int im_contrast_surface_raw( IMAGE *, IMAGE *, int, int );

int im_resize_linear( IMAGE *, IMAGE *, int, int );
int im_mpercent( IMAGE *, double, int * );
int im_shrink( IMAGE *, IMAGE *, double, double );
int im_embed( IMAGE *, IMAGE *, int, int, int, int, int );

int im_stretch3( IMAGE *in, IMAGE *out, double dx, double dy );
int im_rank_raw( IMAGE *in, IMAGE *out, int xsize, int ysize, int n );

/* freq_filt
 */
int im_fractsurf( IMAGE *out, int size, double frd );
int im_freqflt( IMAGE *, IMAGE *, IMAGE * );
int im_disp_ps( IMAGE *, IMAGE * );
int im_rotquad( IMAGE *, IMAGE * );
int im_fwfft( IMAGE *, IMAGE * );
int im_invfft( IMAGE *, IMAGE * );
int im_invfftr( IMAGE *, IMAGE * );

/* cimg
 */
int im_greyc_mask( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int iterations, float amplitude, float sharpness, float anisotropy, 
	float alpha, float sigma, float dl, float da, float gauss_prec, 
	int interpolation, int fast_approx );

/* histogram
 */
int im_maplut( IMAGE *, IMAGE *, IMAGE * );
int im_gammacorrect( IMAGE *, IMAGE *, double );
int im_heq( IMAGE *in, IMAGE *out, int bandno );
int im_hist( IMAGE *in, IMAGE *out, int bandno );
int im_hist_indexed( IMAGE *index, IMAGE *value, IMAGE *out );
int im_histeq( IMAGE *in, IMAGE *out );
int im_histnorm( IMAGE *in, IMAGE *out );
int im_histcum( IMAGE *in, IMAGE *out );
int im_histgr( IMAGE *in, IMAGE *out, int bandno );
int im_histnD( IMAGE *in, IMAGE *out, int bins );
int im_histplot( IMAGE *hist, IMAGE *histplot );
int im_histspec( IMAGE *hin, IMAGE *href, IMAGE *lut );
int im_hsp( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_identity( IMAGE *lut, int bands );
int im_identity_ushort( IMAGE *lut, int bands, int sz );
int im_lhisteq( IMAGE *in, IMAGE *out, int xwin, int ywin );
int im_lhisteq_raw( IMAGE *in, IMAGE *out, int xwin, int ywin );
int im_invertlut( DOUBLEMASK *input, IMAGE *output, int lut_size );
int im_buildlut( DOUBLEMASK *input, IMAGE *output );
int im_stdif( IMAGE *in, IMAGE *out,
	double a, double m0, double b, double s0, int xwin, int ywin );
int im_stdif_raw( IMAGE *in, IMAGE *out,
	double a, double m0, double b, double s0, int xwin, int ywin );
int im_tone_build_range( IMAGE *out,
	int in_max, int out_max,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );
int im_tone_build( IMAGE *out,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );
int im_tone_analyse( IMAGE *in, IMAGE *lut,
	double Ps, double Pm, double Ph, double S, double M, double H );
int im_ismonotonic( IMAGE *lut, int *out );
int im_tone_map( IMAGE *in, IMAGE *out, IMAGE *lut );
int im_project( IMAGE *in, IMAGE *hout, IMAGE *vout );

/* other
 */
int im_feye( IMAGE *image,
	const int xsize, const int ysize, const double factor );
int im_eye( IMAGE *image,
	const int xsize, const int ysize, const double factor );
int im_zone( IMAGE *im, int size );
int im_fzone( IMAGE *im, int size );
int im_grey( IMAGE *im, const int xsize, const int ysize );
int im_fgrey( IMAGE *im, const int xsize, const int ysize );
int im_make_xy( IMAGE *out, const int xsize, const int ysize );
int im_benchmarkn( IMAGE *in, IMAGE *out, int n );
int im_benchmark2( IMAGE *in, double *out );

int im_cooc_matrix( IMAGE *im, IMAGE *m,
	int xp, int yp, int xs, int ys, int dx, int dy, int flag );
int im_cooc_asm( IMAGE *m, double *asmoment );
int im_cooc_contrast( IMAGE *m, double *contrast );
int im_cooc_correlation( IMAGE *m, double *correlation );
int im_cooc_entropy( IMAGE *m, double *entropy );

int im_glds_matrix( IMAGE *im, IMAGE *m,
	int xpos, int ypos, int xsize, int ysize, int dx, int dy );
int im_glds_asm( IMAGE *m, double *asmoment );
int im_glds_contrast( IMAGE *m, double *contrast );
int im_glds_entropy( IMAGE *m, double *entropy );
int im_glds_mean( IMAGE *m, double *mean );

int im_simcontr( IMAGE *image, int xs, int ys );
int im_sines( IMAGE *image,
	int xsize, int ysize, double horfreq, double verfreq );
int im_spatres( IMAGE *in,  IMAGE *out, int step );

int im_rightshift_size( IMAGE *in, IMAGE *out, int xshift, int yshift, int band_fmt );

/* mosaicing
 */
int im_lrmerge( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int dx, int dy, int mwidth );
int im_tbmerge( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int dx, int dy, int mwidth );

int im_lrmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int mwidth );
int im_tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int mwidth );

int im_lrmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth );
int im_tbmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth );

int im_lrmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth );
int im_tbmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth );

int im_global_balance( IMAGE *in, IMAGE *out, double gamma );
int im_global_balancef( IMAGE *in, IMAGE *out, double gamma );

int im_match_linear( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2 );
int im_match_linear_search( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize );

int im_affinei( IMAGE *in, IMAGE *out, 
	VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh );
int im_affinei_all( IMAGE *in, IMAGE *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy ) ;
int im_correl( IMAGE *ref, IMAGE *sec,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y );
int im_remosaic( IMAGE *in, IMAGE *out,
	const char *old_str, const char *new_str );

int im_align_bands( IMAGE *in, IMAGE *out );
int im_maxpos_subpel( IMAGE *in, double *x, double *y );

/* inplace
 */
int im_plotmask( IMAGE *, int, int, PEL *, PEL *, Rect * );
int im_smear( IMAGE *, int, int, Rect * );
int im_smudge( IMAGE *, int, int, Rect * );
int im_paintrect( IMAGE *, Rect *, PEL * );
int im_circle( IMAGE *, int, int, int, int );
int im_insertplace( IMAGE *, IMAGE *, int, int );
int im_line( IMAGE *, int, int, int, int, int );
int im_fastlineuser();
int im_readpoint( IMAGE *, int, int, PEL * );
int im_flood( IMAGE *, int, int, PEL *, Rect * );
int im_flood_blob( IMAGE *, int, int, PEL *, Rect * );
int im_flood_blob_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink );
int im_flood_other( IMAGE *mask, IMAGE *test, int x, int y, int serial );
int im_flood_other_copy( IMAGE *mask, IMAGE *test, IMAGE *out, 
	int x, int y, int serial );
int im_segment( IMAGE *test, IMAGE *mask, int *segments );
int im_lineset( IMAGE *in, IMAGE *out, IMAGE *mask, IMAGE *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v );

/* matrix
 */
DOUBLEMASK *im_mattrn( DOUBLEMASK *, const char * );
DOUBLEMASK *im_matcat( DOUBLEMASK *, DOUBLEMASK *, const char * );
DOUBLEMASK *im_matmul( DOUBLEMASK *, DOUBLEMASK *, const char * );

DOUBLEMASK *im_lu_decomp( const DOUBLEMASK *mat, const char *name );
int im_lu_solve( const DOUBLEMASK *lu, double *vec );
DOUBLEMASK *im_matinv( const DOUBLEMASK *mat, const char *name );
int im_matinv_inplace( DOUBLEMASK *mat );


int *im_ivector();
float *im_fvector();
double *im_dvector();
void im_free_ivector();
void im_free_fvector();
void im_free_dvector();

int **im_imat_alloc();
float **im_fmat_alloc();
double **im_dmat_alloc();
void im_free_imat();
void im_free_fmat();
void im_free_dmat();

int im_invmat( double **, int );

/* video
 */
int im_video_v4l1( IMAGE *im, const char *device,
	int channel, int brightness, int colour, int contrast, int hue,
	int ngrabs );
int im_video_test( IMAGE *im, int brightness, int error );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_PROTO_H*/
