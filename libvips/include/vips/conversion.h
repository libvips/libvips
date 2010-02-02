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

#ifndef IM_CONVERSION_H
#define IM_CONVERSION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

DOUBLEMASK *im_vips2mask( IMAGE *in, const char *out );
int im_mask2vips( DOUBLEMASK *in, IMAGE *out );

int im_copy( IMAGE *in, IMAGE *out );
int im_copy_set( IMAGE *in, IMAGE *out, 
	VipsType type, float xres, float yres, int xoffset, int yoffset );
int im_copy_set_meta( IMAGE *in, IMAGE *out, const char *field, GValue *meta );
int im_copy_morph( IMAGE *in, IMAGE *out, 
	int bands, VipsBandFmt bandfmt, VipsCoding coding );
int im_copy_swap( IMAGE *in, IMAGE *out );
int im_copy_native( IMAGE *in, IMAGE *out, gboolean is_msb_first );
int im_copy_file( IMAGE *in, IMAGE *out );

int im_clip2fmt( IMAGE *in, IMAGE *out, VipsBandFmt fmt );
int im_scale( IMAGE *in, IMAGE *out );
int im_msb( IMAGE *in, IMAGE *out );
int im_msb_band( IMAGE *in, IMAGE *out, int band );

int im_c2amph( IMAGE *in, IMAGE *out );
int im_c2rect( IMAGE *in, IMAGE *out );
int im_ri2c( IMAGE *real_in, IMAGE *imag_in, IMAGE *out );
int im_c2imag( IMAGE *in, IMAGE *out );
int im_c2real( IMAGE *in, IMAGE *out );
int im_scaleps( IMAGE *in, IMAGE *out );

int im_falsecolour( IMAGE *in, IMAGE *out );
int im_gaussnoise( IMAGE *out, int x, int y, double mean, double sigma );

int im_black( IMAGE *out, int width, int height, int bands );
int im_text( IMAGE *out, const char *text, const char *font,
	int width, int alignment, int dpi );

int im_extract_band( IMAGE *in, IMAGE *out, int band );
int im_extract_bands( IMAGE *in, IMAGE *out, int band, int nbands );
int im_extract_area( IMAGE *in, IMAGE *out, int x, int y, int w, int h );
int im_extract_areabands( IMAGE *in, IMAGE *out,
	int left, int top, int width, int height, int band, int nbands );
int im_embed( IMAGE *in, IMAGE *out, int type, 
	int left, int top, int width, int height );
int im_bandjoin( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_gbandjoin( IMAGE **in, IMAGE *out, int n );
int im_insert( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y );
int im_insert_noexpand( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y );
int im_insertset( IMAGE *main, IMAGE *sub, IMAGE *out, int n, int *x, int *y );
int im_lrjoin( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_tbjoin( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_replicate( IMAGE *in, IMAGE *out, int across, int down );
int im_grid( IMAGE *in, IMAGE *out, int tile_height, int across, int down );
int im_wrap( IMAGE *in, IMAGE *out, int x, int y );

int im_fliphor( IMAGE *in, IMAGE *out );
int im_flipver( IMAGE *in, IMAGE *out );
int im_rot90( IMAGE *in, IMAGE *out );
int im_rot180( IMAGE *in, IMAGE *out );
int im_rot270( IMAGE *in, IMAGE *out );

int im_subsample( IMAGE *in, IMAGE *out, int x, int y );
int im_zoom( IMAGE *in, IMAGE *out, int x, int y );

int im_system( IMAGE *im, const char *cmd, char **out );
IMAGE *im_system_image( IMAGE *im, 
	const char *in_format, const char *out_format, const char *cmd_format, 
	char **log );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CONVERSION_H*/
