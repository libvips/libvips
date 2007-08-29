/* im_header_int, im_header_double, im_header_string: output various fields
 * from the VIPS header
 *
 * 9/7/02 JC
 *	- first version
 * 7/6/05
 * 	- now reads meta fields too
 * 	- cleaned up
 *	- added im_header_exists(), im_header_map()
 * 1/8/05
 * 	- now im_header_get_type() and im_header_get() rather than
 * 	  im_header_exists()
 * 4/1/07
 * 	- removed Hist from standard fields ... now a separate function
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Name, offset pair.
 */
typedef struct _HeaderField {
	const char *field;
	glong offset;
} HeaderField;

/* Built in fields and struct offsets.
 */
static HeaderField int_field[] = {
	{ "Xsize", G_STRUCT_OFFSET( IMAGE, Xsize ) },
	{ "Ysize", G_STRUCT_OFFSET( IMAGE, Ysize ) },
	{ "Bands", G_STRUCT_OFFSET( IMAGE, Bands ) },
	{ "Bbits", G_STRUCT_OFFSET( IMAGE, Bbits ) },
	{ "BandFmt", G_STRUCT_OFFSET( IMAGE, BandFmt ) },
	{ "Coding", G_STRUCT_OFFSET( IMAGE, Coding ) },
	{ "Type", G_STRUCT_OFFSET( IMAGE, Type ) },
	{ "Xoffset", G_STRUCT_OFFSET( IMAGE, Xoffset ) },
	{ "Yoffset", G_STRUCT_OFFSET( IMAGE, Yoffset ) }
};

/* These are actually floats :-( how annoying. We report them as doubles for
 * consistency with the im_meta_*() functions.
 */
static HeaderField double_field[] = {
	{ "Xres", G_STRUCT_OFFSET( IMAGE, Xres ) },
	{ "Yres", G_STRUCT_OFFSET( IMAGE, Yres ) }
};

static HeaderField string_field[] = {
	{ "filename", G_STRUCT_OFFSET( IMAGE, filename ) }
};

int
im_header_int( IMAGE *im, const char *field, int *out )
{
	int i;

	for( i = 0; i < IM_NUMBER( int_field ); i++ )
		if( strcmp( field, int_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( int, im, 
				int_field[i].offset );
			break;
		}

	if( i == IM_NUMBER( int_field ) &&
		im_meta_get_int( im, field, out ) ) {
		im_error( "im_header_int", 
			_( "no such int field \"%s\"" ), field );
		return( -1 );
	}

	return( 0 );
}

int
im_header_double( IMAGE *im, const char *field, double *out )
{
	int i;

	for( i = 0; i < IM_NUMBER( double_field ); i++ )
		if( strcmp( field, double_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( float, im, 
				double_field[i].offset );
			break;
		}

	if( i == IM_NUMBER( double_field ) &&
		im_meta_get_double( im, field, out ) ) {
		im_error( "im_header_double", 
			_( "no such double field \"%s\"" ), field );
		return( -1 );
	}

	return( 0 );
}

int
im_header_string( IMAGE *im, const char *field, char **out )
{
	int i;

	for( i = 0; i < IM_NUMBER( string_field ); i++ )
		if( strcmp( field, string_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( char *, im, 
				string_field[i].offset );
			break;
		}

	if( i == IM_NUMBER( string_field ) &&
		im_meta_get_string( im, field, out ) ) {
		im_error( "im_header_string", 
			_( "no such string field \"%s\"" ), field );
		return( -1 );
	}

	return( 0 );
}

GType 
im_header_get_type( IMAGE *im, const char *field )
{
	int i;
	GType type;

	for( i = 0; i < IM_NUMBER( int_field ); i++ )
		if( strcmp( field, int_field[i].field ) == 0 ) 
			return( G_TYPE_INT );
	for( i = 0; i < IM_NUMBER( double_field ); i++ )
		if( strcmp( field, double_field[i].field ) == 0 ) 
			return( G_TYPE_DOUBLE );
	for( i = 0; i < IM_NUMBER( string_field ); i++ )
		if( strcmp( field, string_field[i].field ) == 0 ) 
			return( G_TYPE_STRING );
	if( (type = im_meta_get_type( im, field )) )
		return( type );

	return( 0 );
}

/* Fill value_copy with a copy of the value, -1 on error. value_copy must be 
 * zeroed but uninitialised. User must g_value_unset( value ).
 */
int
im_header_get( IMAGE *im, const char *field, GValue *value_copy )
{
	int i;

	for( i = 0; i < IM_NUMBER( int_field ); i++ ) 
		if( strcmp( field, int_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_INT );
			g_value_set_int( value_copy, 
				G_STRUCT_MEMBER( int, im, 
					int_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < IM_NUMBER( double_field ); i++ ) 
		if( strcmp( field, double_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_DOUBLE );
			g_value_set_double( value_copy, 
				G_STRUCT_MEMBER( float, im, 
					double_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < IM_NUMBER( string_field ); i++ ) 
		if( strcmp( field, string_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_STRING );
			g_value_set_static_string( value_copy, 
				G_STRUCT_MEMBER( char *, im, 
					string_field[i].offset ) );
			return( 0 );
		}

	if( !im_meta_get( im, field, value_copy ) )
		return( 0 );

	return( -1 );
}

static void *
header_map_fn( Meta *meta, im_header_map_fn fn, void *a )
{
	return( fn( meta->im, meta->field, &meta->value, a ) );
}

void *
im_header_map( IMAGE *im, im_header_map_fn fn, void *a )
{
	int i;
	GValue value = { 0 };
	void *result;

	for( i = 0; i < IM_NUMBER( int_field ); i++ ) {
		im_header_get( im, int_field[i].field, &value );
		result = fn( im, int_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	for( i = 0; i < IM_NUMBER( double_field ); i++ ) {
		im_header_get( im, double_field[i].field, &value );
		result = fn( im, double_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	for( i = 0; i < IM_NUMBER( string_field ); i++ ) {
		im_header_get( im, string_field[i].field, &value );
		result = fn( im, string_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	if( im->Meta_traverse && 
		(result = im_slist_map2( im->Meta_traverse, 
			(VSListMap2Fn) header_map_fn, fn, a )) )
		return( result );

	return( NULL );
}
