/* boolean.h
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

#ifndef IM_HEADER_H
#define IM_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips_format_sizeof( VipsBandFormat format );

int vips_image_get_width( VipsImage *image );
int vips_image_get_height( VipsImage *image );
int vips_image_get_bands( VipsImage *image );
VipsBandFormat vips_image_get_format( VipsImage *image );
VipsCoding vips_image_get_coding( VipsImage *image );
VipsInterpretation vips_image_get_interpretation( VipsImage *image );
double vips_image_get_xres( VipsImage *image );
double vips_image_get_yres( VipsImage *image );
int vips_image_get_xoffset( VipsImage *image );
int vips_image_get_yoffset( VipsImage *image );
const char *vips_image_get_filename( VipsImage *image );
const char *vips_image_get_mode( VipsImage *image );

void vips_image_init_fields( VipsImage *image, 
	int xsize, int ysize, int bands, 
	VipsBandFormat format, VipsCoding coding, 
	VipsInterpretation interpretation, 
	float xres, float yres );

int vips_image_copy_fields_array( VipsImage *out, VipsImage *in[] );
int vips_image_copy_fieldsv( VipsImage *out, VipsImage *in1, ... )
	__attribute__((sentinel));
int vips_image_copy_fields( VipsImage *out, VipsImage *in );

int vips_image_get_int( VipsImage *im, const char *field, int *out );
int vips_image_get_double( VipsImage *im, const char *field, double *out );
int vips_image_get_string( VipsImage *im, const char *field, char **out );
int vips_image_get_as_string( VipsImage *im, const char *field, char **out );
GType vips_image_get_typeof( VipsImage *im, const char *field );
int vips_image_get( VipsImage *im, const char *field, GValue *value_copy );

typedef void *(*VipsImageMapFn)( VipsImage *image, 
	const char *field, GValue *value, void *a );
void *vips_image_map( VipsImage *im, VipsImageMapFn fn, void *a );

int vips_image_history_printf( VipsImage *image, const char *format, ... )
	__attribute__((format(printf, 2, 3)));
int vips_image_history_args( VipsImage *image, 
	const char *name, int argc, char *argv[] );
const char *vips_image_get_history( VipsImage *image );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_HEADER_H*/
