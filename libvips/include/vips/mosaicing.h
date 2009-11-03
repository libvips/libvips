/* mosaicing.h
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

#ifndef IM_MOSAICING_H
#define IM_MOSAICING_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

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

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_MOSAICING_H*/
