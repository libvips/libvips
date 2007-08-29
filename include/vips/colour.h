/* Definitions for VIPS colour package.
 *
 * J.Cupitt, 8/4/93
 * 15/7/96 JC
 *	- C++ stuff added
 * 20/2/98 JC
 *	- new display calibration added
 * 26/9/05
 * 	- added IM_ prefix to colour temps
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

#ifndef IM_COLOUR_H
#define IM_COLOUR_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/util.h>

/* Convert degrees->rads and vice-versa. 
 */
#define IM_RAD( r ) (((r) / 360.0) * 2.0 * IM_PI)
#define IM_DEG( a ) (((a) / (2.0 * IM_PI)) * 360.0)

/* Areas under curves for Dxx. 2 degree observer.
 */
#define IM_D93_X0 (89.7400)
#define IM_D93_Y0 (100.0)
#define IM_D93_Z0 (130.7700)

#define IM_D75_X0 (94.9682)
#define IM_D75_Y0 (100.0)
#define IM_D75_Z0 (122.5710)

/* D65 temp 6504.
 */
#define IM_D65_X0 (95.0470)
#define IM_D65_Y0 (100.0)
#define IM_D65_Z0 (108.8827)

#define IM_D55_X0 (95.6831)
#define IM_D55_Y0 (100.0)
#define IM_D55_Z0 (92.0871)

#define IM_D50_X0 (96.4250)
#define IM_D50_Y0 (100.0)
#define IM_D50_Z0 (82.4680)

/* A temp 2856k.
 */
#define IM_A_X0 (109.8503)
#define IM_A_Y0 (100.0)
#define IM_A_Z0 (35.5849)

/* B temp 4874k.
 */
#define IM_B_X0 (99.0720)
#define IM_B_Y0 (100.0)
#define IM_B_Z0 (85.2230)

/* C temp 6774k.
 */
#define IM_C_X0 (98.0700)
#define IM_C_Y0 (100.0)
#define IM_C_Z0 (118.2300)

#define IM_E_X0 (100.0)
#define IM_E_Y0 (100.0)
#define IM_E_Z0 (100.0)

#define IM_D3250_X0 (105.6590)
#define IM_D3250_Y0 (100.0)
#define IM_D3250_Z0 (45.8501)

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

/* Structure for holding the lookup tables for XYZ<=>rgb conversion.
 * Also holds the luminance to XYZ matrix and the inverse one.
 */
struct im_col_tab_disp {
	float	t_Yr2r[1501];		/* Conversion of Yr to r */
	float	t_Yg2g[1501];		/* Conversion of Yg to g */
	float	t_Yb2b[1501];		/* Conversion of Yb to b */
	float	t_r2Yr[1501];		/* Conversion of r to Yr */
	float	t_g2Yg[1501];		/* Conversion of g to Yg */
	float	t_b2Yb[1501];		/* Conversion of b to Yb */
	float	mat_XYZ2lum[3][3];	/* XYZ to Yr, Yg, Yb matrix */
	float	mat_lum2XYZ[3][3];	/* Yr, Yg, Yb to XYZ matrix */
	float rstep, gstep, bstep;
	float ristep, gistep, bistep;
};

/* Colour loading and conversion functions.
 */
void im_col_ab2Ch( float a, float b, float *C, float *h );
void im_col_LCh2ab( float L, float C, float h, float *a, float *b );
void im_col_XYZ2Lab( float X, float Y, float Z, float *L, float *a, float *b );
void im_col_Lab2XYZ( float L, float a, float b, float *X, float *Y, float *Z );
float im_col_pythagoras( float L1, float a1, float b1, 
	float L2, float a2, float b2 );
struct im_col_tab_disp *im_col_make_tables_RGB( 
	IMAGE *im,
	struct im_col_display *d );
int im_col_rgb2XYZ( struct im_col_display *d, 
	struct im_col_tab_disp *table, 
	int r, int g, int b, 
	float *X, float *Y, float *Z );
int im_col_XYZ2rgb( 
	struct im_col_display *d, struct im_col_tab_disp *table, 
	float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret );

float im_col_L2Lucs( float L );
float im_col_Lucs2L( float Lucs );
float im_col_C2Cucs( float C );
float im_col_Cucs2C( float Cucs );
float im_col_Ch2hucs( float C, float h );
float im_col_Chucs2h( float C, float hucs );
double im_col_ab2h( double a, double b );

int im_ICC2display( char *filename, struct im_col_display *dpy );
int im_XYZ2disp( IMAGE *, IMAGE *, struct im_col_display * );
int im_Lab2disp( IMAGE *, IMAGE *, struct im_col_display * );
int im_LabQ2disp( IMAGE *, IMAGE *, struct im_col_display * );
int im_disp2XYZ( IMAGE *, IMAGE *, struct im_col_display * );
int im_disp2Lab( IMAGE *, IMAGE *, struct im_col_display * );

void *im_LabQ2disp_build_table( IMAGE *out, struct im_col_display *d );
int im_LabQ2disp_table( IMAGE *in, IMAGE *out, void *table );

int im_dE_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );
int im_dECMC_fromdisp( IMAGE *, IMAGE *, IMAGE *, struct im_col_display * );
int im_dE00_fromLab( IMAGE *, IMAGE *, IMAGE * );

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
struct im_col_display *im_col_displays( int );
struct im_col_display *im_col_display_name( const char * );

/* Render intents for icc wrappers.
 */
#define IM_INTENT_PERCEPTUAL                 (0)
#define IM_INTENT_RELATIVE_COLORIMETRIC      (1)
#define IM_INTENT_SATURATION                 (2)
#define IM_INTENT_ABSOLUTE_COLORIMETRIC      (3)

int im_icc_present( void );
int im_icc_transform( IMAGE *in, IMAGE *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	int intent );
int im_icc_import( IMAGE *in, IMAGE *out, 
	const char *input_profile_filename, int intent );
int im_icc_import_embedded( IMAGE *in, IMAGE *out, int intent );
int im_icc_export( IMAGE *in, IMAGE *out, 
	const char *output_profile_filename, int intent );
int im_icc_export_depth( IMAGE *in, IMAGE *out, int depth,
	const char *output_profile_filename, int intent );
int im_icc_ac2rc( IMAGE *in, IMAGE *out, const char *profile_filename );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_COLOUR_H*/
