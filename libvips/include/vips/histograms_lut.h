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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_HIST_H
#define IM_HIST_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_maplut( IMAGE *in, IMAGE *out, IMAGE *lut );
int im_gammacorrect( IMAGE *in, IMAGE *out, double exponent );
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
int im_invertlut( DOUBLEMASK *input, IMAGE *output, int lut_size );
int im_buildlut( DOUBLEMASK *input, IMAGE *output );
int im_stdif( IMAGE *in, IMAGE *out,
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
int im_mpercent( IMAGE *in, double percent, int *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_HIST_H*/
