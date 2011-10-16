/* conversion.h
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

#ifndef VIPS_CONVERSION_H
#define VIPS_CONVERSION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/** 
 * VipsExtend:
 * @VIPS_EXTEND_BLACK; extend with black (all 0) pixels
 * @VIPS_EXTEND_COPY; copy the image edges
 * @VIPS_EXTEND_REPEAT; repeat the whole image
 * @VIPS_EXTEND_MIRROR; mirror the whole image
 * @VIPS_EXTEND_WHITE; extend with white (all bits set) pixels
 *
 * See vips_embed(), vips_conv(), vips_affine() and so on.
 *
 * When the edges of an image are extended, you can specify
 * how you want the extension done. 
 *
 * #VIPS_EXTEND_BLACK --- new pixels are black, ie. all bits are zero. 
 *
 * #VIPS_EXTEND_COPY --- each new pixel takes the value of the nearest edge
 * pixel
 *
 * #VIPS_EXTEND_REPEAT --- the image is tiled to fill the new area
 *
 * #VIPS_EXTEND_MIRROR --- the image is reflected and tiled to reduce hash
 * edges
 *
 * #VIPS_EXTEND_WHITE --- new pixels are white, ie. all bits are set
 *
 * We have to specify the exact value of each enum member since we have to 
 * keep these frozen for back compat with vips7.
 *
 * See also: vips_embed().
 */
typedef enum {
	VIPS_EXTEND_BLACK = 0,
	VIPS_EXTEND_COPY = 1,
	VIPS_EXTEND_REPEAT = 2,
	VIPS_EXTEND_MIRROR = 3,
	VIPS_EXTEND_WHITE = 4,
	VIPS_EXTEND_LAST = 5
} VipsExtend;

int vips_copy( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_embed( VipsImage *in, VipsImage **out, 
	int x, int y, int width, int height, ... )
	__attribute__((sentinel));




DOUBLEMASK *im_vips2mask( VipsImage *in, const char *filename );
int im_mask2vips( DOUBLEMASK *in, VipsImage *out );

int im_copy_file( VipsImage *in, VipsImage *out );

int im_clip2fmt( VipsImage *in, VipsImage *out, VipsBandFormat fmt );
int im_scale( VipsImage *in, VipsImage *out );
int im_msb( VipsImage *in, VipsImage *out );
int im_msb_band( VipsImage *in, VipsImage *out, int band );

int im_c2amph( VipsImage *in, VipsImage *out );
int im_c2rect( VipsImage *in, VipsImage *out );
int im_ri2c( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_c2imag( VipsImage *in, VipsImage *out );
int im_c2real( VipsImage *in, VipsImage *out );
int im_scaleps( VipsImage *in, VipsImage *out );

int im_falsecolour( VipsImage *in, VipsImage *out );
int im_gaussnoise( VipsImage *out, int x, int y, double mean, double sigma );

int im_black( VipsImage *out, int x, int y, int bands );
int im_text( VipsImage *out, const char *text, const char *font,
	int width, int alignment, int dpi );

int im_extract_band( VipsImage *in, VipsImage *out, int band );
int im_extract_bands( VipsImage *in, VipsImage *out, int band, int nbands );
int im_extract_area( VipsImage *in, VipsImage *out, 
	int left, int top, int width, int height );
int im_extract_areabands( VipsImage *in, VipsImage *out,
	int left, int top, int width, int height, int band, int nbands );
int im_embed( VipsImage *in, VipsImage *out, 
	int type, int x, int y, int width, int height );
int im_bandjoin( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_gbandjoin( VipsImage **in, VipsImage *out, int n );
int im_insert( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
int im_insert_noexpand( VipsImage *main, VipsImage *sub, VipsImage *out, int x, int y );
int im_insertset( VipsImage *main, VipsImage *sub, VipsImage *out, int n, int *x, int *y );
int im_lrjoin( VipsImage *left, VipsImage *right, VipsImage *out );
int im_tbjoin( VipsImage *top, VipsImage *bottom, VipsImage *out );
int im_replicate( VipsImage *in, VipsImage *out, int across, int down );
int im_grid( VipsImage *in, VipsImage *out, int tile_height, int across, int down );
int im_wrap( VipsImage *in, VipsImage *out, int x, int y );

int im_fliphor( VipsImage *in, VipsImage *out );
int im_flipver( VipsImage *in, VipsImage *out );
int im_rot90( VipsImage *in, VipsImage *out );
int im_rot180( VipsImage *in, VipsImage *out );
int im_rot270( VipsImage *in, VipsImage *out );

int im_subsample( VipsImage *in, VipsImage *out, int xshrink, int yshrink );
int im_zoom( VipsImage *in, VipsImage *out, int xfac, int yfac );

int im_system( VipsImage *im, const char *cmd, char **out );
VipsImage *im_system_image( VipsImage *im, 
	const char *in_format, const char *out_format, const char *cmd_format, 
	char **log );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_CONVERSION_H*/
