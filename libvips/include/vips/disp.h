/* VIPS display conversions.
 *
 * 23/10/09
 * 	- from colour.h
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

#ifndef IM_DISP_H
#define IM_DISP_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Two kinds of display. A DISP_BARCO does gamma correction etc etc for us and
 * needs only a colour space transform, a DISP_DUMB is an ordinary display and
 * needs a full range of corrections. 
 */
enum im_col_disp_type {
	DISP_BARCO = 0,
	DISP_DUMB
};

/* Structure for holding information about a display device. See the BARCO
 * papers for details on the fields.
 */
struct im_col_display {
	/* All private.
	 */
	/*< private >*/
	char *d_name;			/* Display name */
	enum im_col_disp_type d_type;	/* Display type */
	float d_mat[3][3]; 		/* XYZ -> luminance matrix */
	float d_YCW;			/* Luminosity of reference white */
	float d_xCW;			/* x, y for reference white */
	float d_yCW;
	float d_YCR;			/* Light o/p for reference white */
	float d_YCG;
	float d_YCB;
	int d_Vrwr;			/* Pixel values for ref. white */
	int d_Vrwg;
	int d_Vrwb;
	float d_Y0R;			/* Residual light for black pixel */
	float d_Y0G;
	float d_Y0B;
	float d_gammaR;			/* Gamma values for the three guns */
	float d_gammaG;
	float d_gammaB;
	float d_B;			/* 'Background' (like brightness) */
	float d_P;			/* 'Picture' (like contrast) */
};

int im_col_rgb2XYZ( struct im_col_display *d, 
	int r, int g, int b, 
	float *X, float *Y, float *Z );
int im_col_XYZ2rgb( 
	struct im_col_display *d, 
	float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret );

int im_XYZ2disp( IMAGE *in, IMAGE *out, struct im_col_display *d );
int im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *d );
int im_LabQ2disp( IMAGE *in, IMAGE *out, struct im_col_display *d );
int im_disp2XYZ( IMAGE *in, IMAGE *out, struct im_col_display *d );
int im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *d );

/* Colour display values and arrays
	&im_col_screen_white,	index 0
	&im_col_SPARC_white,	index 1
	&im_col_D65_white,	index 2
	&im_col_barco_white,	index 3
	&im_col_mitsubishi,	index 4
	&im_col_relative,	index 5
	&ultra2,		index 6 
	&srgb_profile,		index 7 
 */
struct im_col_display *im_col_displays( int n );
struct im_col_display *im_col_display_name( const char *name );

void *im_LabQ2disp_build_table( IMAGE *out, struct im_col_display *d );
int im_LabQ2disp_table( IMAGE *in, IMAGE *out, void *table );

int im_dE_fromdisp( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	struct im_col_display *d );
int im_dECMC_fromdisp( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	struct im_col_display *d );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_DISP_H*/
