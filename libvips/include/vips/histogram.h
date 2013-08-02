/* histograms_lut.h
 *
 * 3/11/09
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_HISTOGRAM_H
#define VIPS_HISTOGRAM_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips_maplut( VipsImage *in, VipsImage **out, VipsImage *lut, ... )
	__attribute__((sentinel));




int im_histgr( VipsImage *in, VipsImage *out, int bandno );
int im_histnD( VipsImage *in, VipsImage *out, int bins );
int im_hist_indexed( VipsImage *index, VipsImage *value, VipsImage *out );

int im_invertlut( DOUBLEMASK *input, VipsImage *output, int lut_size );
int im_project( VipsImage *in, VipsImage *hout, VipsImage *vout );

int im_histnorm( VipsImage *in, VipsImage *out );
int im_histcum( VipsImage *in, VipsImage *out );
int im_histeq( VipsImage *in, VipsImage *out );
int im_histspec( VipsImage *in, VipsImage *ref, VipsImage *out );
int im_ismonotonic( VipsImage *lut, int *out );
int im_histplot( VipsImage *in, VipsImage *out );

int im_hsp( VipsImage *in, VipsImage *ref, VipsImage *out );
int im_mpercent( VipsImage *in, double percent, int *out );
int im_mpercent_hist( VipsImage *hist, double percent, int *out );

int im_heq( VipsImage *in, VipsImage *out, int bandno );
int im_lhisteq( VipsImage *in, VipsImage *out, int xwin, int ywin );
int im_stdif( VipsImage *in, VipsImage *out,
	double a, double m0, double b, double s0, int xwin, int ywin );

int im_tone_build_range( VipsImage *out,
	int in_max, int out_max,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );
int im_tone_build( VipsImage *out,
	double Lb, double Lw, double Ps, double Pm, double Ph,
	double S, double M, double H );
int im_tone_analyse( VipsImage *in, VipsImage *out,
	double Ps, double Pm, double Ph, double S, double M, double H );
int im_tone_map( VipsImage *in, VipsImage *out, VipsImage *lut );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_HISTOGRAM_H*/
