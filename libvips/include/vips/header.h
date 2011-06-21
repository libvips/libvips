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

#ifndef VIPS_HEADER_H
#define VIPS_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * VIPS_META_EXIF_NAME:
 *
 * The name that JPEG read and write operations use for the image's EXIF data.
 */
#define VIPS_META_EXIF_NAME "exif-data"

/**
 * VIPS_META_ICC_NAME:
 *
 * The name we use to attach an ICC profile. The file read and write
 * operations for TIFF, JPEG, PNG and others use this item of metadata to
 * attach and save ICC profiles. The profile is updated by the
 * vips_icc_transform() operations.
 */
#define VIPS_META_ICC_NAME "icc-profile-data"

/**
 * VIPS_META_XML:
 *
 * The original XML that was used to code the metadata after reading a VIPS
 * format file.
 */
#define VIPS_META_XML "xml-header"

/**
 * VIPS_META_RESOLUTION_UNIT:
 *
 * The JPEG and TIFF read and write operations use this to record the
 * file's preferred unit for resolution.
 */
#define VIPS_META_RESOLUTION_UNIT "resolution-unit"

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
void *vips_image_get_data( VipsImage *image );

void vips_image_init_fields( VipsImage *image, 
	int xsize, int ysize, int bands, 
	VipsBandFormat format, VipsCoding coding, 
	VipsInterpretation interpretation, 
	float xres, float yres );

int vips_image_copy_fields_array( VipsImage *out, VipsImage *in[] );
int vips_image_copy_fieldsv( VipsImage *out, VipsImage *in1, ... )
	__attribute__((sentinel));
int vips_image_copy_fields( VipsImage *out, VipsImage *in );

int vips_image_set( VipsImage *image, const char *field, GValue *value );
int vips_image_get( VipsImage *image, const char *field, GValue *value_copy );
GType vips_image_get_typeof( VipsImage *image, const char *field );
gboolean vips_image_remove( VipsImage *image, const char *field );
typedef void *(*VipsImageMapFn)( VipsImage *image, 
	const char *field, GValue *value, void *a );
void *vips_image_map( VipsImage *image, VipsImageMapFn fn, void *a );

/**
 * VIPS_TYPE_SAVE_STRING:
 *
 * The #GType for an "vips_save_string".
 */
#define VIPS_TYPE_SAVE_STRING (vips_save_string_get_type())
GType vips_save_string_get_type( void );
const char *vips_save_string_get( const GValue *value );
void vips_save_string_set( GValue *value, const char *str );
void vips_save_string_setf( GValue *value, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));

/**
 * VIPS_TYPE_AREA:
 *
 * The #GType for an #vips_area.
 */
#define VIPS_TYPE_AREA (vips_area_get_type())
GType vips_area_get_type( void );

/**
 * VIPS_TYPE_REF_STRING:
 *
 * The #GType for an #vips_refstring.
 */
#define VIPS_TYPE_REF_STRING (vips_ref_string_get_type())
GType vips_ref_string_get_type( void );
int vips_ref_string_set( GValue *value, const char *str );
const char *vips_ref_string_get( const GValue *value );
size_t vips_ref_string_get_length( const GValue *value );

/**
 * VIPS_TYPE_BLOB:
 *
 * The #GType for an #vips_blob.
 */

/* Also used for eg. vips_local() and friends.
 */
typedef int (*VipsCallbackFn)( void *a, void *b );

#define VIPS_TYPE_BLOB (vips_blob_get_type())
GType vips_blob_get_type( void );
void *vips_blob_get( const GValue *value, size_t *length );
int vips_blob_set( GValue *value, VipsCallbackFn free_fn, 
	void *data, size_t length ); 

int vips_image_set_area( VipsImage *image, 
	const char *field, VipsCallbackFn free_fn, void *data );
int vips_image_get_area( VipsImage *image, const char *field, void **data );
int vips_image_set_string( VipsImage *image, 
	const char *field, const char *str );
int vips_image_get_string( VipsImage *image, const char *field, char **out );
int vips_image_set_blob( VipsImage *image, const char *field, 
	VipsCallbackFn free_fn, void *data, size_t length );
int vips_image_get_blob( VipsImage *image, const char *field, 
	void **data, size_t *length );

int vips_image_get_int( VipsImage *image, const char *field, int *out );
int vips_image_set_int( VipsImage *image, const char *field, int i );
int vips_image_get_double( VipsImage *image, const char *field, double *out );
int vips_image_set_double( VipsImage *image, const char *field, double d );
int vips_image_get_as_string( VipsImage *image, const char *field, char **out );

int vips_image_history_printf( VipsImage *image, const char *format, ... )
	__attribute__((format(printf, 2, 3)));
int vips_image_history_args( VipsImage *image, 
	const char *name, int argc, char *argv[] );
const char *vips_image_get_history( VipsImage *image );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_HEADER_H*/
