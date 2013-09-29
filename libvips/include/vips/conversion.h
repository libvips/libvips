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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_CONVERSION_H
#define VIPS_CONVERSION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef enum {
	VIPS_EXTEND_BLACK,
	VIPS_EXTEND_COPY,
	VIPS_EXTEND_REPEAT,
	VIPS_EXTEND_MIRROR,
	VIPS_EXTEND_WHITE,
	VIPS_EXTEND_BACKGROUND,
	VIPS_EXTEND_LAST
} VipsExtend;

typedef enum {
	VIPS_DIRECTION_HORIZONTAL,
	VIPS_DIRECTION_VERTICAL,
	VIPS_DIRECTION_LAST
} VipsDirection;

typedef enum {
	VIPS_ALIGN_LOW,
	VIPS_ALIGN_CENTRE,
	VIPS_ALIGN_HIGH,
	VIPS_ALIGN_LAST
} VipsAlign;

typedef enum {
	VIPS_ANGLE_0,
	VIPS_ANGLE_90,
	VIPS_ANGLE_180,
	VIPS_ANGLE_270,
	VIPS_ANGLE_LAST
} VipsAngle;

int vips_copy( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_tilecache( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_linecache( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_sequential( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_cache( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_copy_file( VipsImage *in, VipsImage **out, ... )
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
int vips_grid( VipsImage *in, VipsImage **out, 
	int tile_height, int across, int down, ... )
	__attribute__((sentinel));
int vips_wrap( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_rot( VipsImage *in, VipsImage **out, VipsAngle angle, ... )
	__attribute__((sentinel));
int vips_zoom( VipsImage *in, VipsImage **out, int xfac, int yfac, ... )
	__attribute__((sentinel));
int vips_subsample( VipsImage *in, VipsImage **out, int xfac, int yfac, ... )
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
int vips_scale( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_msb( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_bandjoin( VipsImage **in, VipsImage **out, int n, ... )
	__attribute__((sentinel));
int vips_bandjoin2( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_bandmean( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_bandbool( VipsImage *in, VipsImage **out, 
	VipsOperationBoolean operation, ... )
	__attribute__((sentinel));
int vips_bandand( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_bandor( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_bandeor( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_recomb( VipsImage *in, VipsImage **out, VipsImage *m, ... )
	__attribute__((sentinel));

int vips_ifthenelse( VipsImage *cond, VipsImage *in1, VipsImage *in2, 
	VipsImage **out, ... )
	__attribute__((sentinel));
int vips_flatten( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_falsecolour( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_gammacorrect( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));

int im_insertset( VipsImage *main, VipsImage *sub, VipsImage *out, int n, int *x, int *y );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_CONVERSION_H*/
