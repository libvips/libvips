/* the GTypes we define
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_TYPE_H
#define VIPS_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* A very simple boxed type for testing. Just holds an int.
 */
typedef struct _VipsThing {
	int i;
} VipsThing;

/**
 * VIPS_TYPE_THING:
 *
 * The #GType for a #VipsThing.
 */
#define VIPS_TYPE_THING (vips_thing_get_type())
GType vips_thing_get_type( void );
VipsThing *vips_thing_new( int i );
int vips_thing_get_i( VipsThing *thing );

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

	/* Reference count and lock. 
	 *
	 * We could use an atomic int, but this is not a high-traffic data
	 * structure, so a simple GMutex is OK.
	 */
	int count;
	GMutex *lock;		

	/* Things like ICC profiles need their own free functions.
	 */
	VipsCallbackFn free_fn;

	/* If we are holding an array (for example, an array of double), the
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
void vips__type_leak( void );

VipsArea *vips_area_new( VipsCallbackFn free_fn, void *data );
VipsArea *vips_area_new_blob( VipsCallbackFn free_fn, 
	void *data, size_t length );
VipsArea *vips_area_new_array( GType type, size_t sizeof_type, int n );
VipsArea *vips_area_new_array_object( int n );

void *vips_area_get_data( VipsArea *area, 
	size_t *length, int *n, GType *type, size_t *sizeof_type );

/**
 * VIPS_TYPE_AREA:
 *
 * The #GType for a #VipsArea.
 */
#define VIPS_TYPE_AREA (vips_area_get_type())
GType vips_area_get_type( void );

/**
 * VIPS_TYPE_SAVE_STRING:
 *
 * The #GType for a #VipsSaveString.
 */
#define VIPS_TYPE_SAVE_STRING (vips_save_string_get_type())
GType vips_save_string_get_type( void );

/**
 * VIPS_TYPE_REF_STRING:
 *
 * The #GType for a #VipsRefString.
 */
#define VIPS_TYPE_REF_STRING (vips_ref_string_get_type())
GType vips_ref_string_get_type( void );

/**
 * VIPS_TYPE_BLOB:
 *
 * The %GType for a #VipsBlob.
 */
#define VIPS_TYPE_BLOB (vips_blob_get_type())
GType vips_blob_get_type( void );

/**
 * VIPS_TYPE_ARRAY_DOUBLE:
 *
 * The #GType for a #VipsArrayDouble.
 */
#define VIPS_TYPE_ARRAY_DOUBLE (vips_array_double_get_type())
typedef VipsArea VipsArrayDouble;
VipsArrayDouble *vips_array_double_new( const double *array, int n );
VipsArrayDouble *vips_array_double_newv( int n, ... );
GType vips_array_double_get_type( void );

/**
 * VIPS_TYPE_ARRAY_INT:
 *
 * The #GType for a #VipsArrayInt.
 */
#define VIPS_TYPE_ARRAY_INT (vips_array_int_get_type())
typedef VipsArea VipsArrayInt;
VipsArrayInt *vips_array_int_new( const int *array, int n );
VipsArrayInt *vips_array_int_newv( int n, ... );
GType vips_array_int_get_type( void );

/**
 * VIPS_TYPE_ARRAY_IMAGE:
 *
 * The #GType for a #VipsArrayImage.
 */
#define VIPS_TYPE_ARRAY_IMAGE (vips_array_image_get_type())
typedef VipsArea VipsArrayImage;
GType vips_array_image_get_type( void );

void vips_value_set_area( GValue *value, VipsCallbackFn free_fn, void *data );
void *vips_value_get_area( const GValue *value, size_t *length );

const char *vips_value_get_save_string( const GValue *value );
void vips_value_set_save_string( GValue *value, const char *str );
void vips_value_set_save_stringf( GValue *value, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));

const char *vips_value_get_ref_string( const GValue *value, size_t *length );
int vips_value_set_ref_string( GValue *value, const char *str );

void *vips_value_get_blob( const GValue *value, size_t *length );
void vips_value_set_blob( GValue *value, 
	VipsCallbackFn free_fn, void *data, size_t length );

void vips_value_set_array( GValue *value, 
	int n, GType type, size_t sizeof_type );
void *vips_value_get_array( const GValue *value, 
	int *n, GType *type, size_t *sizeof_type );

double *vips_value_get_array_double( const GValue *value, int *n );
int vips_value_set_array_double( GValue *value, const double *array, int n );

VipsImage **vips_value_get_array_image( const GValue *value, int *n );
int vips_value_set_array_image( GValue *value, VipsImage **array, int n );

int *vips_value_get_array_int( const GValue *value, int *n );
int vips_value_set_array_int( GValue *value, const int *array, int n );

GObject **vips_value_get_array_object( const GValue *value, int *n );
int vips_value_set_array_object( GValue *value, int n );

void vips__meta_init_types( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_TYPE_H*/
