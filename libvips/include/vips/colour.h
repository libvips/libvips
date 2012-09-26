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

#ifndef VIPS_COLOUR_H
#define VIPS_COLOUR_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Areas under curves for Dxx. 2 degree observer.
 */
#define VIPS_D93_X0 (89.7400)
#define VIPS_D93_Y0 (100.0)
#define VIPS_D93_Z0 (130.7700)

#define VIPS_D75_X0 (94.9682)
#define VIPS_D75_Y0 (100.0)
#define VIPS_D75_Z0 (122.5710)

/* D65 temp 6504.
 */
#define VIPS_D65_X0 (95.0470)
#define VIPS_D65_Y0 (100.0)
#define VIPS_D65_Z0 (108.8827)

#define VIPS_D55_X0 (95.6831)
#define VIPS_D55_Y0 (100.0)
#define VIPS_D55_Z0 (92.0871)

#define VIPS_D50_X0 (96.4250)
#define VIPS_D50_Y0 (100.0)
#define VIPS_D50_Z0 (82.4680)

/* A temp 2856k.
 */
#define VIPS_A_X0 (109.8503)
#define VIPS_A_Y0 (100.0)
#define VIPS_A_Z0 (35.5849)

/* B temp 4874k.
 */
#define VIPS_B_X0 (99.0720)
#define VIPS_B_Y0 (100.0)
#define VIPS_B_Z0 (85.2230)

/* C temp 6774k.
 */
#define VIPS_C_X0 (98.0700)
#define VIPS_C_Y0 (100.0)
#define VIPS_C_Z0 (118.2300)

#define VIPS_E_X0 (100.0)
#define VIPS_E_Y0 (100.0)
#define VIPS_E_Z0 (100.0)

#define VIPS_D3250_X0 (105.6590)
#define VIPS_D3250_Y0 (100.0)
#define VIPS_D3250_Z0 (45.8501)

/**
 * VipsIntent:
 * @VIPS_INTENT_PERCEPTUAL: perceptual rendering intent
 * @VIPS_INTENT_RELATIVE: relative colorimetric rendering intent
 * @VIPS_INTENT_SATURATION: saturation rendering intent
 * @VIPS_INTENT_ABSOLUTE: absolute colorimetric rendering intent
 *
 * The rendering intent. #VIPS_INTENT_ABSOLUTE is best for
 * scientific work, #VIPS_INTENT_RELATIVE is usually best for 
 * accurate communication with other imaging libraries.
 */
typedef enum {
	VIPS_INTENT_PERCEPTUAL = 0,
	VIPS_INTENT_RELATIVE,
	VIPS_INTENT_SATURATION,
	VIPS_INTENT_ABSOLUTE
} VipsIntent;

int vips_colour_convert( VipsImage *in, VipsImage **out, 
	VipsInterpretation space, ... )
	__attribute__((sentinel));

int vips_LabQ2sRGB( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_rad2float( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_float2rad( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabS2LabQ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabQ2LabS( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabQ2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2LabQ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LCh2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2LCh( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Yxy2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_UCS2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_XYZ2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_XYZ2sRGB( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_sRGB2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LCh2UCS( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_UCS2LCh( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_XYZ2Yxy( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Yxy2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabS2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2LabS( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_icc_present( void );
int vips_icc_transform( VipsImage *in, VipsImage **out, 
	const char *output_profile, ... )
	__attribute__((sentinel));
int vips_icc_import( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_icc_export( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_icc_ac2rc( VipsImage *in, VipsImage *out, 
	const char *profile_filename );

void vips_col_Lab2XYZ( float L, float a, float b, 
	float *X, float *Y, float *Z );
void vips_col_XYZ2Lab( float X, float Y, float Z, 
	float *L, float *a, float *b );
double vips_col_ab2h( double a, double b );
void vips_col_ab2Ch( float a, float b, float *C, float *h );
void vips_col_Ch2ab( float C, float h, float *a, float *b );

float vips_col_L2Lucs( float L );
float vips_col_C2Cucs( float C );
float vips_col_Ch2hucs( float C, float h );

void vips_col_make_tables_UCS( void );
float vips_col_Lucs2L( float Lucs );
float vips_col_Cucs2C( float Cucs );
float vips_col_Chucs2h( float C, float hucs );

int vips_col_XYZ2sRGB( float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret );
int vips_col_sRGB2XYZ( int r, int g, int b, float *X, float *Y, float *Z );


/* Colour loading and conversion functions.
 */
float im_col_pythagoras( float L1, float a1, float b1, 
	float L2, float a2, float b2 );

float im_col_dECMC( 
	float L1, float a1, float b1, float L2, float a2, float b2 );
float im_col_dE00( 
	float L1, float a1, float b1, float L2, float a2, float b2 );

int im_dECMC_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE00_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE_fromXYZ( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );

int im_lab_morph( VipsImage *in, VipsImage *out,
	DOUBLEMASK *mask,
	double L_offset, double L_scale,
	double a_scale, double b_scale );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_COLOUR_H*/
