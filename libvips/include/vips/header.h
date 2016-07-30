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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
 * VIPS_META_XMP_NAME:
 *
 * The name that read and write operations use for the image's XMP data.
 */
#define VIPS_META_XMP_NAME "xmp-data"

/**
 * VIPS_META_IPCT_NAME:
 *
 * The name that read and write operations use for the image's IPCT data.
 */
#define VIPS_META_IPCT_NAME "ipct-data"

/**
 * VIPS_META_PHOTOSHOP_NAME:
 *
 * The name that TIFF read and write operations use for the image's
 * TIFFTAG_PHOTOSHOP data.
 */
#define VIPS_META_PHOTOSHOP_NAME "photoshop-data"

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
 * VIPS_META_IMAGEDESCRIPTION:
 *
 * The IMAGEDESCRIPTION tag. Often has useful metadata. 
 */
#define VIPS_META_IMAGEDESCRIPTION "image-description"

/**
 * VIPS_META_RESOLUTION_UNIT:
 *
 * The JPEG and TIFF read and write operations use this to record the
 * file's preferred unit for resolution.
 */
#define VIPS_META_RESOLUTION_UNIT "resolution-unit"

/**
 * VIPS_META_LOADER:
 *
 * Record the name of the original loader here. Handy for hinting file formats
 * and for debugging.
 */
#define VIPS_META_LOADER "vips-loader"

guint64 vips_format_sizeof( VipsBandFormat format );
guint64 vips_format_sizeof_unsafe( VipsBandFormat format );

int vips_image_get_width( const VipsImage *image );
int vips_image_get_height( const VipsImage *image );
int vips_image_get_bands( const VipsImage *image );
VipsBandFormat vips_image_get_format( const VipsImage *image );
VipsBandFormat vips_image_guess_format( const VipsImage *image );
VipsCoding vips_image_get_coding( const VipsImage *image );
VipsInterpretation vips_image_get_interpretation( const VipsImage *image );
VipsInterpretation vips_image_guess_interpretation( const VipsImage *image );
double vips_image_get_xres( const VipsImage *image );
double vips_image_get_yres( const VipsImage *image );
int vips_image_get_xoffset( const VipsImage *image );
int vips_image_get_yoffset( const VipsImage *image );
const char *vips_image_get_filename( const VipsImage *image );
const char *vips_image_get_mode( const VipsImage *image );
double vips_image_get_scale( const VipsImage *image );
double vips_image_get_offset( const VipsImage *image );
const void *vips_image_get_data( VipsImage *image );

void vips_image_init_fields( VipsImage *image, 
	int xsize, int ysize, int bands, 
	VipsBandFormat format, VipsCoding coding, 
	VipsInterpretation interpretation, 
	double xres, double yres );

void vips_image_set( VipsImage *image, const char *field, GValue *value );
int vips_image_get( const VipsImage *image, 
	const char *field, GValue *value_copy );
int vips_image_get_as_string( const VipsImage *image, 
	const char *field, char **out );
GType vips_image_get_typeof( const VipsImage *image, const char *field );
gboolean vips_image_remove( VipsImage *image, const char *field );
typedef void *(*VipsImageMapFn)( VipsImage *image, 
	const char *field, GValue *value, void *a );
void *vips_image_map( VipsImage *image, VipsImageMapFn fn, void *a );

void vips_image_set_area( VipsImage *image, 
	const char *field, VipsCallbackFn free_fn, void *data );
int vips_image_get_area( const VipsImage *image, 
	const char *field, void **data );
void vips_image_set_blob( VipsImage *image, const char *field, 
	VipsCallbackFn free_fn, void *data, size_t length );
int vips_image_get_blob( const VipsImage *image, const char *field, 
	void **data, size_t *length );

int vips_image_get_int( const VipsImage *image, const char *field, int *out );
void vips_image_set_int( VipsImage *image, const char *field, int i );
int vips_image_get_double( const VipsImage *image, 
	const char *field, double *out );
void vips_image_set_double( VipsImage *image, const char *field, double d );
int vips_image_get_string( const VipsImage *image, 
	const char *field, const char **out );
void vips_image_set_string( VipsImage *image, 
	const char *field, const char *str );

int vips_image_history_printf( VipsImage *image, const char *format, ... )
	__attribute__((format(printf, 2, 3)));
int vips_image_history_args( VipsImage *image, 
	const char *name, int argc, char *argv[] );
const char *vips_image_get_history( VipsImage *image );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_HEADER_H*/
