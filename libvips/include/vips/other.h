/* other.h
 *
 * 20/9/09
 * 	- from proto.h
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

#ifndef IM_OTHER_H
#define IM_OTHER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

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

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_OTHER_H*/
