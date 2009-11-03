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

/* cimg
 */
int im_greyc_mask( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int iterations, float amplitude, float sharpness, float anisotropy, 
	float alpha, float sigma, float dl, float da, float gauss_prec, 
	int interpolation, int fast_approx );

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
