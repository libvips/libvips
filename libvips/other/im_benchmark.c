/* @(#) Do a complicated compound operation for benchmarking the threading 
 * @(#) system. Input should be a large LABQ image, output is a large sRGB
 * @(#) image.
 * @(#) 
 * @(#) Usage:
 * @(#) 
 * @(#) int im_benchmark( IMAGE *in, IMAGE *out )
 * @(#) 
 * @(#) Returns 0 on sucess and -1 on error.
 * @(#) 
 *
 * 6/10/06
 *	- hacked in
 * 27/11/06
 *	- added im_benchmarkn()
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*

VIPS SMP benchmark
------------------

This is adapted from the system used to generate images for POD:

  http://cima.ng-london.org.uk/~john/POD

Images from a 10k by 10k studio digital camera are colour processed, resized,
cropped and sharpened. 

The original POD script was written in nip (see below). This operation is a 
reimplementation in vanilla C to make it easier to run (and less fragile!).

This thing was originally processing images off a remote server over a 100mbit
network. No attempt was made to make it quick (there was no point): you 
could make it a lot faster very easily.

------ benchmark in nip2 -----------
#!/home/john/vips/bin/nip2 -s

// get command-line arguments

image_path = argv?1;
crop_id = parse_pint argv?2;
crop_left = parse_pint argv?3;
crop_top = parse_pint argv?4;
crop_width = parse_pint argv?5;
crop_height = parse_pint argv?6;
width = parse_pint argv?7;
height = parse_pint argv?8;
sharp = parse_pint argv?9;

// scale down by this much to undo photographic's relativisation 
darken = Vector [1.18, 1, 1];

// fudge factor in XYZ to get a match under NGC lights on uv-durable paper
white_point_adjust = Vector [1.06, 1, 1.01];

// brighten by this in XYZ to get relative colorimetry
brighten = 1.5;

// blacks down by this much in LAB
blacks_down = Vector [-2, 0, 0];

// sharpen params for 400, 300, 200 and 150 dpi
// just change the size of the area we search
sharpen_params_table = [
	[ 11, 2.5, 40, 20, 0.5, 1.5 ],
	[ 7, 2.5, 40, 20, 0.5, 1.5 ],
	[ 5, 2.5, 40, 20, 0.5, 1.5 ],
	[ 3, 2.5, 40, 20, 0.5, 1.5 ]
];

// convert D65 XYZ to D50 XYZ
D652D50 = recomb D652D50_direct;

stage_crop in
	= extract_area crop_left crop_top crop_width crop_height in, 
		 crop_id != 0
	= in;

// fit within a width / height
stage_shrink image 
	= image, factor > 1;	// never upscale
	= resize factor factor Interpolate.BILINEAR image
{
        hfactor = width / get_width image;
        vfactor = height / get_height image;
        factor = min_pair hfactor vfactor;
}

// unphotoize, go to xyz, convert to D50, adjust white point, back to lab
stage_colour in
        = if in?0 > 99 then Vector [100, 0, 0] else in'''
{
	// back to absolute
        in' = in / darken;

	xyz = colour_transform_to Image_type.XYZ in';

	xyz' = D652D50 xyz * white_point_adjust * brighten;

        in'' = colour_transform_to Image_type.LAB xyz';

	// shadows down
	in''' = in'' + blacks_down;
}

stage_sharp in
	= (sharpen params?0 params?1 params?2 params?3 params?4 params?5 @
		colour_transform_to Image_type.LABQ) in
{
	params = sharpen_params_table?sharp;
}

// This was:
// 
// stage_srgb in
//	= (icc_export 8 "$VIPSHOME/share/nip2/data/sRGB.icm" 1 @
//		colour_transform_to Image_type.LABQ) in;
//
// but that uses lcms which is single-threaded. So for this benchmark, we use
// VIPS's own ->sRGB converter, which is less accurate but does thread.
stage_srgb in
	= colour_transform_to Image_type.sRGB in;

main = (get_image @ stage_srgb @ 
	stage_sharp @ stage_colour @ stage_shrink @ stage_crop @ 
	colour_transform_to Image_type.LAB @ Image_file) image_path;
------ benchmark in nip2 -----------

 */

/* The main part of the benchmark ... transform labq to labq. Chain several of
 * these together to get a CPU-bound operation.
 */
static int
benchmark( IMAGE *in, IMAGE *out )
{
	IMAGE *t[18];
	double one[3] = { 1.0, 1.0, 1.0 };
	double zero[3] = { 0.0, 0.0, 0.0 };
	double darken[3] = { 1.0 / 1.18, 1.0, 1.0 };
	double whitepoint[3] = { 1.06, 1.0, 1.01 };
	double shadow[3] = { -2, 0, 0 };
	double white[3] = { 100, 0, 0 };
	DOUBLEMASK *d652d50 = im_create_dmaskv( "d652d50", 3, 3,
		1.13529, -0.0604663, -0.0606321,
		0.0975399, 0.935024, -0.0256156,
		-0.0336428, 0.0414702, 0.994135 );

	im_add_close_callback( out, 
		(im_callback_fn) im_free_dmask, d652d50, NULL );

	return( 	
		/* Set of descriptors for this operation.
		 */
		im_open_local_array( out, t, 18, "im_benchmark", "p" ) ||

		/* Unpack to float.
		 */
		im_LabQ2Lab( in, t[0] ) ||

		/* Crop 100 pixels off all edges.
		 */
		im_extract_area( t[0], t[1], 
			100, 100, t[0]->Xsize - 200, t[0]->Ysize - 200 ) ||

		/* Shrink by 10%, bilinear interp.
		 */
		im_affinei_all( t[1], t[2],
			vips_interpolate_bilinear_static(),
			0.9, 0, 0, 0.9, 
			0, 0 ) || 

		/* Find L ~= 100 areas (white surround).
		 */
		im_extract_band( t[2], t[3], 0 ) ||
		im_moreconst( t[3], t[4], 99 ) ||

		/* Adjust white point and shadows.
		 */
		im_lintra_vec( 3, darken, t[2], zero, t[5] ) ||
		im_Lab2XYZ( t[5], t[6] ) ||
		im_recomb( t[6], t[7], d652d50 ) ||
		im_lintra_vec( 3, whitepoint, t[7], zero, t[8] ) ||
		im_lintra( 1.5, t[8], 0.0, t[9] ) ||
		im_XYZ2Lab( t[9], t[10] ) ||
		im_lintra_vec( 3, one, t[10], shadow, t[11] ) ||

		/* Make a solid white image.
		 */
		im_black( t[12], t[4]->Xsize, t[4]->Ysize, 3 ) ||
		im_lintra_vec( 3, zero, t[12], white, t[13] ) ||

		/* Reattach border.
		 */
		im_ifthenelse( t[4], t[13], t[11], t[14] ) ||

		/* Sharpen.
		 */
		im_Lab2LabQ( t[14], t[15] ) ||
		im_sharpen( t[15], out, 11, 2.5, 40, 20, 0.5, 1.5 ) 
	);
}

/* Chain n benchmarks together to get a CPU-bound operation.
 */
int
im_benchmarkn( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *t[2];

	if( n == 0 )
		/* To sRGB.
		 */
		return( im_LabQ2disp( in, out, im_col_displays( 7 ) ) );
	else 
		return( im_open_local_array( out, t, 2, "benchmarkn", "p" ) ||

			benchmark( in, t[0] ) ||

			/* Expand back to the original size again ...
			 * benchmark does a 200 pixel crop plus a 10% shrink,
			 * so if we chain many of them together the image gets
			 * too small.
			 */
			im_affinei_all( t[0], t[1],
				vips_interpolate_bilinear_static(),
				(double) in->Xsize / t[0]->Xsize, 0, 0, 
				(double) in->Ysize / t[0]->Ysize, 
				0, 0 ) || 

			im_benchmarkn( t[1], out, n - 1 ) );
}

int
im_benchmark2( IMAGE *in, double *out )
{
        IMAGE *t;

        return(
		!(t = im_open_local( in, "benchmarkn", "p" )) ||
                im_benchmarkn( in, t, 1 ) ||
                im_avg( t, out ) 
	);
}

