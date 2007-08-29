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

/* Reserved header names.
 */
#define IM_META_EXIF_NAME "exif-data"
#define IM_META_ICC_NAME "icc-profile-data"
#define IM_META_XML "xml-header"

/* Types we add for meta fields.
 */
#define IM_TYPE_SAVE_STRING (im_save_string_get_type())
GType im_save_string_get_type( void );
const char *im_save_string_get( const GValue *value );
void im_save_string_set( GValue *value, const char *str );
void im_save_string_setf( GValue *value, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));

#define IM_TYPE_AREA (im_area_get_type())
GType im_area_get_type( void );

#define IM_TYPE_REF_STRING (im_ref_string_get_type())
GType im_ref_string_get_type( void );
int im_ref_string_set( GValue *value, const char *str );
const char *im_ref_string_get( const GValue *value );
size_t im_ref_string_get_length( const GValue *value );

#define IM_TYPE_BLOB (im_blob_get_type())
GType im_blob_get_type( void );
void *im_blob_get( const GValue *value, size_t *data_length );
int im_blob_set( GValue *value, im_callback_fn free_fn, 
	void *data, size_t length ); 

/* What we store in the Meta hash table. We can't just use GHashTable's 
 * key/value pairs, since we need to iterate over meta in Meta_traverse order.
 *
 * We don't refcount at this level ... large meta values are refcounted by
 * their GValue implementation, see eg. MetaArea below.
 */
typedef struct _Meta {
	IMAGE *im;

	char *field;			/* strdup() of field name */
	GValue value;			/* copy of value */
} Meta;

int im_meta_set( IMAGE *, const char *field, GValue * );
int im_meta_get( IMAGE *, const char *field, GValue * );
GType im_meta_get_type( IMAGE *im, const char *field );

int im_meta_set_int( IMAGE *, const char *field, int i );
int im_meta_get_int( IMAGE *, const char *field, int *i );
int im_meta_set_double( IMAGE *, const char *field, double d );
int im_meta_get_double( IMAGE *, const char *field, double *d );
int im_meta_set_area( IMAGE *, const char *field, im_callback_fn, void * );
int im_meta_get_area( IMAGE *, const char *field, void **data );
int im_meta_set_string( IMAGE *, const char *field, const char *str );
int im_meta_get_string( IMAGE *, const char *field, char **str );
int im_meta_set_blob( IMAGE *im, const char *field, 
	im_callback_fn free_fn, void *blob, size_t blob_length );
int im_meta_get_blob( IMAGE *im, const char *field, 
	void **blob, size_t *blob_length );

/* Internal.
 */
void im__meta_init_types( void );
void im__meta_destroy( IMAGE *im );
int im__meta_cp( IMAGE *, const IMAGE * );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*!IM_META_H*/
