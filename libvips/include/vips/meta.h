/* Metadata API.
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_META_H
#define IM_META_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * IM_META_EXIF_NAME:
 *
 * The name that JPEG read and write operations use for the image's EXIF data.
 */
#define IM_META_EXIF_NAME "exif-data"

/**
 * IM_META_ICC_NAME:
 *
 * The name we use to attach an ICC profile. The file read and write
 * operations for TIFF, JPEG, PNG and others use this item of metadata to
 * attach and save ICC profiles. The profile is updated by the
 * im_icc_transform() operations.
 */
#define IM_META_ICC_NAME "icc-profile-data"

/**
 * IM_META_XML:
 *
 * The original XML that was used to code the metadata after reading a VIPS
 * format file.
 */
#define IM_META_XML "xml-header"

/**
 * IM_META_RESOLUTION_UNIT:
 *
 * The JPEG and TIFF read and write operations use this to record the
 * file's preferred unit for resolution.
 */
#define IM_META_RESOLUTION_UNIT "resolution-unit"

/**
 * IM_TYPE_SAVE_STRING:
 *
 * The #GType for an "im_save_string".
 */
#define IM_TYPE_SAVE_STRING (im_save_string_get_type())
GType im_save_string_get_type( void );
const char *im_save_string_get( const GValue *value );
void im_save_string_set( GValue *value, const char *str );
void im_save_string_setf( GValue *value, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));

/**
 * IM_TYPE_AREA:
 *
 * The #GType for an #im_area.
 */
#define IM_TYPE_AREA (im_area_get_type())
GType im_area_get_type( void );

/**
 * IM_TYPE_REF_STRING:
 *
 * The #GType for an #im_refstring.
 */
#define IM_TYPE_REF_STRING (im_ref_string_get_type())
GType im_ref_string_get_type( void );
int im_ref_string_set( GValue *value, const char *str );
const char *im_ref_string_get( const GValue *value );
size_t im_ref_string_get_length( const GValue *value );

/**
 * IM_TYPE_BLOB:
 *
 * The #GType for an #im_blob.
 */

/* Also used for eg. im_local() and friends.
 */
typedef int (*im_callback_fn)( void *a, void *b );

#define IM_TYPE_BLOB (im_blob_get_type())
GType im_blob_get_type( void );
void *im_blob_get( const GValue *value, size_t *length );
int im_blob_set( GValue *value, im_callback_fn free_fn, 
	void *data, size_t length ); 

int im_meta_set( VipsImage *im, const char *field, GValue *value );
gboolean im_meta_remove( VipsImage *im, const char *field );
int im_meta_get( VipsImage *im, const char *field, GValue *value_copy );
GType im_meta_get_typeof( VipsImage *im, const char *field );

int im_meta_set_int( VipsImage *im, const char *field, int i );
int im_meta_get_int( VipsImage *im, const char *field, int *i );
int im_meta_set_double( VipsImage *im, const char *field, double d );
int im_meta_get_double( VipsImage *im, const char *field, double *d );
int im_meta_set_area( VipsImage *im, 
	const char *field, im_callback_fn free_fn, void *data );
int im_meta_get_area( VipsImage *im, const char *field, void **data );
int im_meta_set_string( VipsImage *im, const char *field, const char *str );
int im_meta_get_string( VipsImage *im, const char *field, char **str );
int im_meta_set_blob( VipsImage *im, const char *field, 
	im_callback_fn free_fn, void *data, size_t length );
int im_meta_get_blob( VipsImage *im, const char *field, 
	void **data, size_t *length );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*!IM_META_H*/
