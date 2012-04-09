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

struct im_col_display;

int vips_LabQ2disp( VipsImage *in, VipsImage **out, 
	struct im_col_display *disp, ... )
	__attribute__((sentinel));
int vips_rad2float( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_float2rad( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabS2LabQ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LabQ2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2LabQ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_LCh2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Yxy2Lab( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_UCS2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_Lab2XYZ( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_XYZ2disp( VipsImage *in, VipsImage **out, 
	struct im_col_display *disp, ... )
	__attribute__((sentinel));

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

/* Colour loading and conversion functions.
 */
void im_col_ab2Ch( float a, float b, float *C, float *h );
void im_col_Ch2ab( float C, float h, float *a, float *b );
void im_col_XYZ2Lab( float X, float Y, float Z, float *L, float *a, float *b );
void im_col_Lab2XYZ( float L, float a, float b, float *X, float *Y, float *Z );
float im_col_pythagoras( float L1, float a1, float b1, 
	float L2, float a2, float b2 );

void im_col_make_tables_UCS( void );

float im_col_L2Lucs( float L );
float im_col_Lucs2L( float Lucs );
float im_col_C2Cucs( float C );
float im_col_Cucs2C( float Cucs );
float im_col_Ch2hucs( float C, float h );
float im_col_Chucs2h( float C, float hucs );
double im_col_ab2h( double a, double b );

float im_col_dECMC( 
	float L1, float a1, float b1, float L2, float a2, float b2 );
float im_col_dE00( 
	float L1, float a1, float b1, float L2, float a2, float b2 );

int im_LCh2Lab( VipsImage *in, VipsImage *out );
int im_LabQ2XYZ( VipsImage *in, VipsImage *out );
int im_rad2float( VipsImage *in, VipsImage *out );
int im_float2rad( VipsImage *in, VipsImage *out );
int im_LCh2UCS( VipsImage *in, VipsImage *out );
int im_Lab2LCh( VipsImage *in, VipsImage *out );
int im_Lab2LabQ( VipsImage *in, VipsImage *out );
int im_Lab2LabS( VipsImage *in, VipsImage *out );
int im_Lab2XYZ( VipsImage *in, VipsImage *out );
int im_Lab2XYZ_temp( VipsImage *in, VipsImage *out, 
	double X0, double Y0, double Z0 );
int im_Lab2UCS( VipsImage *in, VipsImage *out );
int im_LabQ2Lab( VipsImage *in, VipsImage *out );
int im_LabQ2LabS( VipsImage *in, VipsImage *out );
int im_LabS2LabQ( VipsImage *in, VipsImage *out );
int im_LabS2Lab( VipsImage *in, VipsImage *out );
int im_UCS2XYZ( VipsImage *in, VipsImage *out );
int im_UCS2LCh( VipsImage *in, VipsImage *out );
int im_UCS2Lab( VipsImage *in, VipsImage *out );
int im_XYZ2Lab( VipsImage *in, VipsImage *out );
int im_XYZ2Lab_temp( VipsImage *in, VipsImage *out, 
	double X0, double Y0, double Z0 );
int im_XYZ2UCS( VipsImage *in, VipsImage *out );
int im_sRGB2XYZ( VipsImage *in, VipsImage *out );
int im_XYZ2sRGB( VipsImage *in, VipsImage *out );
int im_Yxy2XYZ( VipsImage *in, VipsImage *out );
int im_XYZ2Yxy( VipsImage *in, VipsImage *out );

int im_dECMC_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE00_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE_fromXYZ( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_dE_fromLab( VipsImage *in1, VipsImage *in2, VipsImage *out );

int im_lab_morph( VipsImage *in, VipsImage *out,
	DOUBLEMASK *mask,
	double L_offset, double L_scale,
	double a_scale, double b_scale );

/* Render intents for icc wrappers.
 */
typedef enum {
	IM_INTENT_PERCEPTUAL = 0,
	IM_INTENT_RELATIVE_COLORIMETRIC,
	IM_INTENT_SATURATION,
	IM_INTENT_ABSOLUTE_COLORIMETRIC
} VipsIntent;

int im_icc_present( void );
int im_icc_transform( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	VipsIntent intent );
int im_icc_import( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename, VipsIntent intent );
int im_icc_import_embedded( VipsImage *in, VipsImage *out, VipsIntent intent );
int im_icc_export_depth( VipsImage *in, VipsImage *out, int depth,
	const char *output_profile_filename, VipsIntent intent );
int im_icc_ac2rc( VipsImage *in, VipsImage *out, const char *profile_filename );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_COLOUR_H*/
