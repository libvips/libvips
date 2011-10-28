/* area.h
 *
 * 27/10/11
 * 	- from header.h
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

#ifndef VIPS_AREA_H
#define VIPS_AREA_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Also used for eg. vips_local() and friends.
 */
typedef int (*VipsCallbackFn)( void *a, void *b );

/* A ref-counted area of memory. Can hold arrays of things as well.
 */
typedef struct _VipsArea {
	void *data;
	size_t length;		/* 0 if not known */

	/* If this area represents an array, the number of elements in the
	 * array. Equal to length / sizeof(element).
	 */
	int n;

	/*< private >*/

	/* Reference count.
	 */
	int count;

	/* Things like ICC profiles need their own free functions.
	 */
	VipsCallbackFn free_fn;

	/* If we are holding an array (for exmaple, an array of double), the
	 * GType of the elements and their size. 0 for not known.
	 *
	 * n is always length / sizeof_type, we keep it as a member for
	 * convenience.
	 */
	GType type;
	size_t sizeof_type;
} VipsArea;

VipsArea *vips_area_copy( VipsArea *area );
void vips_area_unref( VipsArea *area );

VipsArea *vips_area_new( VipsCallbackFn free_fn, void *data );
VipsArea *vips_area_new_blob( VipsCallbackFn free_fn, 
	void *blob, size_t blob_length );
VipsArea *vips_area_new_array( GType type, size_t sizeof_type, int n );
VipsArea *vips_area_new_array_object( int n );

/**
 * VIPS_TYPE_AREA:
 *
 * The #GType for a #vips_area.
 */
#define VIPS_TYPE_AREA (vips_area_get_type())
int vips_value_set_area( GValue *value, VipsCallbackFn free_fn, void *data );
void *vips_value_get_area( const GValue *value, size_t *length );
GType vips_area_get_type( void );

/**
 * VIPS_TYPE_SAVE_STRING:
 *
 * The #GType for a "vips_save_string".
 */
#define VIPS_TYPE_SAVE_STRING (vips_save_string_get_type())
const char *vips_value_get_save_string( const GValue *value );
void vips_value_set_save_string( GValue *value, const char *str );
void vips_value_set_save_stringf( GValue *value, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
GType vips_save_string_get_type( void );

/**
 * VIPS_TYPE_REF_STRING:
 *
 * The #GType for a #vips_refstring.
 */
#define VIPS_TYPE_REF_STRING (vips_ref_string_get_type())
const char *vips_value_get_ref_string( const GValue *value, size_t *length );
int vips_value_set_ref_string( GValue *value, const char *str );
GType vips_ref_string_get_type( void );

/**
 * VIPS_TYPE_BLOB:
 *
 * The #GType for a #vips_blob.
 */
#define VIPS_TYPE_BLOB (vips_blob_get_type())
void *vips_value_get_blob( const GValue *value, size_t *length );
int vips_value_set_blob( GValue *value, 
	VipsCallbackFn free_fn, void *data, size_t length );
GType vips_blob_get_type( void );

int vips_value_set_array( GValue *value, 
	GType type, size_t sizeof_type, int n );
void *vips_value_get_array( const GValue *value, 
	int *n, GType *type, size_t *sizeof_type );

/**
 * VIPS_TYPE_ARRAY_DOUBLE:
 *
 * The #GType for a #vips_array_double.
 */
#define VIPS_TYPE_ARRAY_DOUBLE (vips_array_double_get_type())
double *vips_value_get_array_double( const GValue *value, int *n );
int vips_value_set_array_double( GValue *value, const double *array, int n );
GType vips_array_double_get_type( void );

/**
 * VIPS_TYPE_ARRAY_IMAGE:
 *
 * The #GType for a #vips_array_image.
 */
#define VIPS_TYPE_ARRAY_IMAGE (vips_array_image_get_type())
GObject **vips_value_get_array_object( const GValue *value, int *n );
int vips_value_set_array_object( GValue *value, int n );
GType vips_array_image_get_type( void );

void vips__meta_init_types( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_AREA_H*/
