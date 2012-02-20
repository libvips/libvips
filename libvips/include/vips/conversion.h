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
 * @VIPS_EXTEND_BLACK: extend with black (all 0) pixels
 * @VIPS_EXTEND_COPY: copy the image edges
 * @VIPS_EXTEND_REPEAT: repeat the whole image
 * @VIPS_EXTEND_MIRROR: mirror the whole image
 * @VIPS_EXTEND_WHITE: extend with white (all bits set) pixels
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

/** 
 * VipsDirection:
 * @VIPS_DIRECTION_HORIZONTAL: left-right 
 * @VIPS_DIRECTION_VERTICAL: top-bottom
 *
 * See vips_flip(), vips_join() and so on.
 *
 * Operations like vips_flip() need to be told whether to flip left-right or
 * top-bottom. 
 *
 * See also: vips_flip(), vips_join().
 */
typedef enum {
	VIPS_DIRECTION_HORIZONTAL,
	VIPS_DIRECTION_VERTICAL,
	VIPS_DIRECTION_LAST
} VipsDirection;

/** 
 * VipsAlign:
 * @VIPS_ALIGN_LOW: align low coordinate edge
 * @VIPS_ALIGN_CENTRE: align centre
 * @VIPS_ALIGN_HIGH: align high coordinate edge
 *
 * See vips_join() and so on.
 *
 * Operations like vips_join() need to be told whether to align images on the
 * low or high coordinate edge, or centre.
 *
 * See also: vips_join().
 */
typedef enum {
	VIPS_ALIGN_LOW,
	VIPS_ALIGN_CENTRE,
	VIPS_ALIGN_HIGH,
	VIPS_ALIGN_LAST
} VipsAlign;

/** 
 * VipsAngle:
 * @VIPS_ANGLE_0: no rotate
 * @VIPS_ANGLE_90: 90 degrees anti-clockwise
 * @VIPS_ANGLE_180: 180 degree rotate
 * @VIPS_ANGLE_270: 90 degrees clockwise
 *
 * See vips_rot() and so on.
 *
 * Fixed rotate angles.
 *
 * See also: vips_rot().
 */
typedef enum {
	VIPS_ANGLE_0,
	VIPS_ANGLE_90,
	VIPS_ANGLE_180,
	VIPS_ANGLE_270,
	VIPS_ANGLE_LAST
} VipsAngle;

/** 
 * VipsCacheStrategy:
 * @VIPS_CACHE_RANDOM: expect random access
 * @VIPS_CACHE_SEQUENTIAL: expect sequential access
 *
 * See vips_tilecache() and friends.
 *
 * Used to hint to caches about the expected access pattern. RANDOM might mean
 * LRU eviction, SEQUENTIAL might mean top-most eviction.
 *
 * See also: vips_tilecache().
 */
typedef enum {
	VIPS_CACHE_RANDOM,
	VIPS_CACHE_SEQUENTIAL,
	VIPS_CACHE_LAST
} VipsCacheStrategy;

int vips_copy( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_tilecache( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_sequential( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cache( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_embed( VipsImage *in, VipsImage **out, 
	int x, int y, int width, int height, ... )
	__attribute__((sentinel));
int vips_flip( VipsImage *in, VipsImage **out, VipsDirection direction, ... )
	__attribute__((sentinel));
int vips_insert( VipsImage *main, VipsImage *sub, VipsImage **out, 
	int x, int y, ... )
	__attribute__((sentinel));
int vips_join( VipsImage *main, VipsImage *sub, VipsImage **out, 
	VipsDirection direction, ... )
	__attribute__((sentinel));
int vips_extract_area( VipsImage *input, VipsImage **output, 
	int left, int top, int width, int height, ... )
	__attribute__((sentinel));
int vips_extract_band( VipsImage *input, VipsImage **output, int band, ... )
	__attribute__((sentinel));
int vips_replicate( VipsImage *in, VipsImage **out, int across, int down, ... )
	__attribute__((sentinel));

int vips_cast( VipsImage *in, VipsImage **out, VipsBandFormat format, ... )
	__attribute__((sentinel));
int vips_cast_uchar( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_char( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_ushort( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_short( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_uint( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_int( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_float( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_double( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_complex( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cast_dpcomplex( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_bandjoin( VipsImage **in, VipsImage **out, int n, ... )
	__attribute__((sentinel));
int vips_bandjoin2( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_bandmean( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_recomb( VipsImage *in, VipsImage **out, VipsImage *m, ... )
	__attribute__((sentinel));
int vips_black( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_rot( VipsImage *in, VipsImage **out, VipsAngle angle, ... )
	__attribute__((sentinel));
int vips_ifthenelse( VipsImage *cond, VipsImage *in1, VipsImage *in2, 
	VipsImage **out, ... )
	__attribute__((sentinel));






int im_copy_file( VipsImage *in, VipsImage *out );

int im_scale( VipsImage *in, VipsImage *out );
int im_msb( VipsImage *in, VipsImage *out );
int im_msb_band( VipsImage *in, VipsImage *out, int band );

int im_scaleps( VipsImage *in, VipsImage *out );

int im_falsecolour( VipsImage *in, VipsImage *out );
int im_gaussnoise( VipsImage *out, int x, int y, double mean, double sigma );

int im_text( VipsImage *out, const char *text, const char *font,
	int width, int alignment, int dpi );

int im_insertset( VipsImage *main, VipsImage *sub, VipsImage *out, int n, int *x, int *y );
int im_grid( VipsImage *in, VipsImage *out, int tile_height, int across, int down );
int im_wrap( VipsImage *in, VipsImage *out, int x, int y );

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
