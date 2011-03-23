/* get, set and copy image header fields
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
 * 29/8/09
 * 	- im_header_get_type() renamed as im_header_get_typeof() to prevent
 * 	  confusion with GObject-style type definers
 * 1/10/09
 * 	- rename as header.c
 * 	- gtkdoc comments
 * 22/3/11
 * 	- rename fields for vips8
 * 	- move to vips_ prefix
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: header
 * @short_description: get, set and walk image headers
 * @stability: Stable
 * @see_also: <link linkend="libvips-meta">meta</link>,
 * <link linkend="libvips-check">check</link>
 * @include: vips/vips.h
 *
 * These functions let you get at image header data (including metadata) in a
 * uniform way. They are handy for language bindings but less useful for C
 * users.
 *
 * They first search the 
 * VIPS header
 * fields (see <link linkend="libvips-image">image</link>), then search for 
 * a metadata field of that name (see
 * <link linkend="libvips-meta">meta</link>).
 * Use im_header_get_typeof() to test for the 
 * existance and #GType
 * of a header field.
 *
 * See <link linkend="libvips-meta">meta</link>
 * for a set of functions for adding new metadata to an image.
 */

/* Name, offset pair.
 */
typedef struct _HeaderField {
	const char *field;
	glong offset;
} HeaderField;

/* Built in fields and struct offsets.
 */

static HeaderField int_field[] = {
	{ "width", G_STRUCT_OFFSET( VipsImage, Xsize ) },
	{ "height", G_STRUCT_OFFSET( VipsImage, Ysize ) },
	{ "bands", G_STRUCT_OFFSET( VipsImage, Bands ) },
	{ "format", G_STRUCT_OFFSET( VipsImage, BandFmt ) },
	{ "coding", G_STRUCT_OFFSET( VipsImage, Coding ) },
	{ "interpretation", G_STRUCT_OFFSET( VipsImage, Type ) },
	{ "xoffset", G_STRUCT_OFFSET( VipsImage, Xoffset ) },
	{ "yoffset", G_STRUCT_OFFSET( VipsImage, Yoffset ) }
};

/* These are actually floats :-( how annoying. We report them as doubles for
 * consistency with the im_meta_*() functions.
 */
static HeaderField double_field[] = {
	{ "xres", G_STRUCT_OFFSET( VipsImage, Xres ) },
	{ "yres", G_STRUCT_OFFSET( VipsImage, Yres ) }
};

static HeaderField string_field[] = {
	{ "filename", G_STRUCT_OFFSET( VipsImage, filename ) }
};

/* Old names we keep around for back-compat. We never loop over these with
 * map, but we do check them when we look up fields by name.
 */
static HeaderField old_int_field[] = {
	{ "Xsize", G_STRUCT_OFFSET( VipsImage, Xsize ) },
	{ "Ysize", G_STRUCT_OFFSET( VipsImage, Ysize ) },
	{ "Bands", G_STRUCT_OFFSET( VipsImage, Bands ) },
	{ "Bbits", G_STRUCT_OFFSET( VipsImage, Bbits ) },
	{ "BandFmt", G_STRUCT_OFFSET( VipsImage, BandFmt ) },
	{ "Coding", G_STRUCT_OFFSET( VipsImage, Coding ) },
	{ "Type", G_STRUCT_OFFSET( VipsImage, Type ) },
	{ "Xoffset", G_STRUCT_OFFSET( VipsImage, Xoffset ) },
	{ "Yoffset", G_STRUCT_OFFSET( VipsImage, Yoffset ) }
};
static HeaderField old_double_field[] = {
	{ "Xres", G_STRUCT_OFFSET( VipsImage, Xres ) },
	{ "Yres", G_STRUCT_OFFSET( VipsImage, Yres ) }
};

/* This is used by (eg.) IM_IMAGE_SIZEOF_ELEMENT() to calculate object
 * size.
 */
const size_t vips__image_sizeof_bandformat[] = {
	sizeof( unsigned char ), 	/* VIPS_FORMAT_UCHAR */
	sizeof( signed char ), 		/* VIPS_FORMAT_CHAR */
	sizeof( unsigned short ), 	/* VIPS_FORMAT_USHORT */
	sizeof( unsigned short ), 	/* VIPS_FORMAT_SHORT */
	sizeof( unsigned int ), 	/* VIPS_FORMAT_UINT */
	sizeof( unsigned int ), 	/* VIPS_FORMAT_INT */
	sizeof( float ), 		/* VIPS_FORMAT_FLOAT */
	2 * sizeof( float ), 		/* VIPS_FORMAT_COMPLEX */
	sizeof( double ), 		/* VIPS_FORMAT_DOUBLE */
	2 * sizeof( double ) 		/* VIPS_FORMAT_DPCOMPLEX */
};

/* Return number of bytes for a band format, or -1 on error.
 */
int 
vips_format_sizeof( VipsBandFormat format )
{
	return( (format < 0 || format > VIPS_FORMAT_DPCOMPLEX) ?
		vips_error( "vips_format_sizeof", 
			_( "unknown band format %d" ), format ), -1 :
		vips__image_sizeof_bandformat[format] );
}

int
vips_image_get_width( VipsImage *image )
{
	return( image->Xsize );
}

int
vips_image_get_height( VipsImage *image )
{
	return( image->Ysize );
}

int
vips_image_get_bands( VipsImage *image )
{
	return( image->Bands );
}

VipsBandFormat
vips_image_get_format( VipsImage *image )
{
	return( image->BandFmt );
}

VipsCoding
vips_image_get_coding( VipsImage *image )
{
	return( image->Coding );
}

VipsInterpretation
vips_image_get_interpretation( VipsImage *image )
{
	return( image->Type );
}

double
vips_image_get_xres( VipsImage *image )
{
	return( image->Xres );
}

double
vips_image_get_yres( VipsImage *image )
{
	return( image->Yres );
}

int
vips_image_get_xoffset( VipsImage *image )
{
	return( image->Xoffset );
}

int
vips_image_get_yoffset( VipsImage *image )
{
	return( image->Yoffset );
}

const char *
vips_image_get_filename( VipsImage *image )
{
	return( image->filename );
}

const char *
vips_image_get_mode( VipsImage *image )
{
	return( image->mode );
}

/**
 * vips_image_init_fields:
 * @image: image to init
 * @xsize: image width
 * @ysize: image height
 * @bands: image bands
 * @bandfmt: band format
 * @coding: image coding
 * @type: image type
 * @xres: horizontal resolution, pixels per millimetre
 * @yres: vertical resolution, pixels per millimetre
 *
 * A convenience function to set the header fields after creating an image.
 * Normally you copy the fields from one of your input images with
 * vips_image_copy_fields() and then make
 * any adjustments you need, but if you are creating an image from scratch,
 * for example im_black() or im_jpeg2vips(), you do need to set all the
 * fields yourself.
 *
 * See also: vips_image_copy_fields().
 */
void 
vips_image_init_fields( VipsImage *image, 
	int xsize, int ysize, int bands, 
	VipsBandFormat format, VipsCoding coding, 
	VipsInterpretation interpretation, 
	float xres, float yres )
{
	g_object_set( image,
		"width", xsize,
		"height", ysize,
		"bands", bands,
		"format", format,
		NULL );

	image->Coding = coding;
	image->Type = interpretation;
	image->Xres = xres;
	image->Yres = yres;
}

/**
 * vips_image_copy_fields_array:
 * @out: image to copy to
 * @in: %NULL-terminated array of images to copy from
 *
 * Copy fields from all the input images to the output image. There must be at
 * least one input image. 
 *
 * The first input image is used to set the main fields of @out (@XSize, @Coding
 * and so on). 
 *
 * Metadata from all the image is merged on to @out, with lower-numbered items 
 * overriding higher. So for example, if @in[0] and @in[1] both have an item
 * called "icc-profile", it's the profile attached to @in[0] that will end up
 * on @out.
 *
 * Image history is completely copied from all @in. @out will have the history
 * of all the intput images.
 *
 * See also: vips_image_copy_fieldsv(), vips_image_copy_fields().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fields_array( VipsImage *out, VipsImage *in[] )
{
	int i;
	int ni;

	g_assert( in[0] );

	out->Xsize = in[0]->Xsize;
	out->Ysize = in[0]->Ysize;
	out->Bands = in[0]->Bands;
	out->Bbits = in[0]->Bbits;
	out->BandFmt = in[0]->BandFmt;
	out->Type = in[0]->Type;
	out->Coding = in[0]->Coding;
	out->Xres = in[0]->Xres;
	out->Yres = in[0]->Yres;
	out->Xoffset = 0;
	out->Yoffset = 0;

	/* Count number of images.
	 */
	for( ni = 0; in[ni]; ni++ ) 
		;

	/* Need to copy last-to-first so that in0 meta will override any
	 * earlier meta.
	 */
	im__meta_destroy( out );
	for( i = ni - 1; i >= 0; i-- ) 
		if( im__meta_cp( out, in[i] ) )
			return( -1 );

	/* Merge hists first to last.
	 */
	for( i = 0; in[i]; i++ )
		out->history_list = im__gslist_gvalue_merge( out->history_list,
			in[i]->history_list );

	return( 0 );
}

/* Max number of images we can handle.
 */
#define MAX_IMAGES (1000)

/**
 * vips_image_copy_fieldsv:
 * @out: image to copy to
 * @in1: first image to copy from
 * @Varargs: %NULL-terminated list of images to copy from
 *
 * Copy fields from all the input images to the output image. A convenience
 * function over vips_image_copy_fields_array(). 
 *
 * See also: vips_image_copy_fields_array(), vips_image_copy_fields().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fieldsv( VipsImage *out, VipsImage *in1, ... )
{
	va_list ap;
	int i;
	VipsImage *in[MAX_IMAGES];

	in[0] = in1;
	va_start( ap, in1 );
	for( i = 1; i < MAX_IMAGES && (in[i] = va_arg( ap, VipsImage * )); i++ ) 
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		vips_error( "im_cp_descv", 
			"%s", _( "too many images" ) );
		return( -1 );
	}

	return( vips_image_copy_fields_array( out, in ) );
}

/**
 * vips_image_copy_fields:
 * @out: image to copy to
 * @in: image to copy from
 *
 * Copy fields from @in to @out. A convenience
 * function over vips_image_copy_fields_array(). 
 *
 * See also: vips_image_copy_fields_array(), vips_image_copy_fieldsv().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fields( VipsImage *out, VipsImage *in )
{
	return( vips_image_copy_fieldsv( out, in, NULL ) ); 
}

/** 
 * vips_image_get_int:
 * @image: image to get the header field from
 * @field: field name
 * @out: return field value
 *
 * Gets @out from @im under the name @field. This function searches for
 * int-valued fields.
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_int( VipsImage *image, const char *field, int *out )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( int_field ); i++ )
		if( strcmp( field, int_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( int, image, 
				int_field[i].offset );
			return( 0 );
		}
	for( i = 0; i < VIPS_NUMBER( old_int_field ); i++ )
		if( strcmp( field, old_int_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( int, image, 
				old_int_field[i].offset );
			return( 0 );
		}

	if( !im_meta_get_int( image, field, out ) ) 
		return( 0 );

	vips_error( "im_header_int", 
		_( "no such int field \"%s\"" ), field );

	return( -1 );
}

/** 
 * vips_image_get_double:
 * @image: image to get the header field from
 * @field: field name
 * @out: return field value
 *
 * Gets @out from @im under the name @field. 
 * This function searches for
 * double-valued fields.
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_double( VipsImage *image, const char *field, double *out )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( double_field ); i++ )
		if( strcmp( field, double_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( float, image, 
				double_field[i].offset );
			return( 0 );
		}
	for( i = 0; i < VIPS_NUMBER( old_double_field ); i++ )
		if( strcmp( field, old_double_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( float, image, 
				old_double_field[i].offset );
			return( 0 );
		}

	if( !im_meta_get_double( image, field, out ) ) 
		return( 0 );

	vips_error( "im_header_double", 
		_( "no such double field \"%s\"" ), field );

	return( -1 );
}

/** 
 * vips_image_get_string:
 * @image: image to get the header field from
 * @field: field name
 * @out: return field value
 *
 * Gets @out from @im under the name @field. 
 * This function searches for string-valued fields. 
 *
 * Do not free @out.
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_string( VipsImage *image, const char *field, char **out )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( string_field ); i++ )
		if( strcmp( field, string_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( char *, image, 
				string_field[i].offset );
			return( 0 );
		}

	if( !im_meta_get_string( image, field, out ) ) 
		return( 0 );

	vips_error( "im_header_string", 
		_( "no such string field \"%s\"" ), field );

	return( -1 );
}

/** 
 * vips_image_get_as_string:
 * @image: image to get the header field from
 * @field: field name
 * @out: return field value as string
 *
 * Gets @out from @im under the name @field. 
 * This function will read any field, returning it as a printable string.
 * You need to free the string with g_free() when you are done with it.
 *
 * See also: vips_image_get(), vips_image_get_typeof().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_as_string( VipsImage *image, const char *field, char **out )
{
	GValue value = { 0 };
	GType type;

	if( vips_image_get( image, field, &value ) )
		return( -1 );

	/* Display the save form, if there is one. This way we display
	 * something useful for ICC profiles, xml fields, etc.
	 */
	type = G_VALUE_TYPE( &value );
	if( g_value_type_transformable( type, IM_TYPE_SAVE_STRING ) ) {
		GValue save_value = { 0 };

		g_value_init( &save_value, IM_TYPE_SAVE_STRING );
		if( !g_value_transform( &value, &save_value ) ) 
			return( -1 );
		*out = g_strdup( im_save_string_get( &save_value ) );
		g_value_unset( &save_value );
	}
	else 
		*out = g_strdup_value_contents( &value );

	g_value_unset( &value );

	return( 0 );
}

/**
 * vips_image_get_typeof:
 * @image: image to test
 * @field: the name to search for
 *
 * Read the GType for a header field. Returns zero if there is no
 * field of that name. 
 *
 * See also: vips_image_get().
 *
 * Returns: the GType of the field, or zero if there is no
 * field of that name.
 */
GType 
vips_image_get_typeof( VipsImage *image, const char *field )
{
	int i;
	GType type;

	for( i = 0; i < VIPS_NUMBER( int_field ); i++ )
		if( strcmp( field, int_field[i].field ) == 0 ) 
			return( G_TYPE_INT );
	for( i = 0; i < VIPS_NUMBER( old_int_field ); i++ )
		if( strcmp( field, old_int_field[i].field ) == 0 ) 
			return( G_TYPE_INT );
	for( i = 0; i < VIPS_NUMBER( double_field ); i++ )
		if( strcmp( field, double_field[i].field ) == 0 ) 
			return( G_TYPE_DOUBLE );
	for( i = 0; i < VIPS_NUMBER( old_double_field ); i++ )
		if( strcmp( field, old_double_field[i].field ) == 0 ) 
			return( G_TYPE_DOUBLE );
	for( i = 0; i < VIPS_NUMBER( string_field ); i++ )
		if( strcmp( field, string_field[i].field ) == 0 ) 
			return( G_TYPE_STRING );
	if( (type = im_meta_get_typeof( image, field )) )
		return( type );

	return( 0 );
}

/* Fill value_copy with a copy of the value, -1 on error. value_copy must be 
 * zeroed but uninitialised. User must g_value_unset( value ).
 */

/**
 * vips_image_get:
 * @image: image to get the field from from
 * @field: the name to give the metadata
 * @value_copy: the GValue is copied into this
 *
 * Fill @value_copy with a copy of the header field. @value_copy must be zeroed 
 * but uninitialised.
 *
 * This will return -1 and add a message to the error buffer if the field
 * does not exist. Use im_header_get_typeof() to test for the 
 * existence
 * of a field first if you are not certain it will be there.
 *
 * For example, to read a double from an image (though of course you would use
 * im_header_double() in practice):
 *
 * |[
 * GValue value = { 0 };
 * double d;
 *
 * if( vips_image_get( image, field, &value ) )
 *   return( -1 );
 *
 * if( G_VALUE_TYPE( &value ) != G_TYPE_DOUBLE ) {
 *   vips_error( "mydomain", 
 *     _( "field \"%s\" is of type %s, not double" ),
 *     field, 
 *     g_type_name( G_VALUE_TYPE( &value ) ) );
 *   g_value_unset( &value );
 *   return( -1 );
 * }
 *
 * d = g_value_get_double( &value );
 * g_value_unset( &value );
 *
 * return( 0 );
 * ]|
 *
 * See also: vips_image_get_typeof(), vips_image_get_double().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get( VipsImage *image, const char *field, GValue *value_copy )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( int_field ); i++ ) 
		if( strcmp( field, int_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_INT );
			g_value_set_int( value_copy, 
				G_STRUCT_MEMBER( int, image, 
					int_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < VIPS_NUMBER( old_int_field ); i++ ) 
		if( strcmp( field, old_int_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_INT );
			g_value_set_int( value_copy, 
				G_STRUCT_MEMBER( int, image, 
					old_int_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < VIPS_NUMBER( double_field ); i++ ) 
		if( strcmp( field, double_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_DOUBLE );
			g_value_set_double( value_copy, 
				G_STRUCT_MEMBER( float, image, 
					double_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < VIPS_NUMBER( old_double_field ); i++ ) 
		if( strcmp( field, old_double_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_DOUBLE );
			g_value_set_double( value_copy, 
				G_STRUCT_MEMBER( float, image, 
					old_double_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < VIPS_NUMBER( string_field ); i++ ) 
		if( strcmp( field, string_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_STRING );
			g_value_set_static_string( value_copy, 
				G_STRUCT_MEMBER( char *, image, 
					string_field[i].offset ) );
			return( 0 );
		}

	if( !im_meta_get( image, field, value_copy ) )
		return( 0 );

	return( -1 );
}

static void *
vips_image_map_fn( Meta *meta, VipsImageMapFn fn, void *a )
{
	return( fn( meta->im, meta->field, &meta->value, a ) );
}

/**
 * vips_image_map:
 * @image: image to map over
 * @fn: function to call for each header field
 * @a: user data for function
 *
 * This function calls @fn for every header field, including every item of 
 * metadata. 
 *
 * Like all _map functions, the user function should return %NULL to continue
 * iteration, or a non-%NULL pointer to indicate early termination.
 *
 * See also: vips_image_get_typeof(), vips_image_get().
 *
 * Returns: %NULL on success, the failing pointer otherwise.
 */
void *
vips_image_map( VipsImage *image, VipsImageMapFn fn, void *a )
{
	int i;
	GValue value = { 0 };
	void *result;

	for( i = 0; i < VIPS_NUMBER( int_field ); i++ ) {
		vips_image_get( image, int_field[i].field, &value );
		result = fn( image, int_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	for( i = 0; i < VIPS_NUMBER( double_field ); i++ ) {
		vips_image_get( image, double_field[i].field, &value );
		result = fn( image, double_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	for( i = 0; i < VIPS_NUMBER( string_field ); i++ ) {
		vips_image_get( image, string_field[i].field, &value );
		result = fn( image, string_field[i].field, &value, a );
		g_value_unset( &value );

		if( result )
			return( result );
	}

	if( image->Meta_traverse && 
		(result = im_slist_map2( image->Meta_traverse, 
			(VSListMap2Fn) vips_image_map_fn, fn, a )) )
		return( result );

	return( NULL );
}

/**
 * vips_image_history_printf:
 * @image: add history liine to this image
 * @format: printf() format string
 * @Varargs: arguments to format string
 *
 * Add a line to the image history. The @format and arguments are expanded, the
 * date and time is appended prefixed with a hash character, and the whole
 * string is appended to the image history and terminated with a newline.
 *
 * For example:
 *
 * |[
 * vips_image_history_printf( image, "vips im_invert %s %s", 
 *   in->filename, out->filename );
 * ]|
 *
 * Might add the string
 *
 * |[
 * "vips im_invert /home/john/fred.v /home/john/jim.v # Fri Apr  3 23:30:35
 * 2009\n"
 * ]|
 *
 * VIPS operations don't add history lines for you because a single action at 
 * the application level might involve many VIPS operations. History must be
 * recorded by the application.
 *
 * See also: im_updatehist().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_history_printf( VipsImage *image, const char *fmt, ... )
{
	va_list args;
	char line[4096];
	time_t timebuf;

	/* Format command. -40, to leave 26 for the ctime, three for the # and
	 * a bit.
	 */
	va_start( args, fmt );
	(void) im_vsnprintf( line, 4096 - 40, fmt, args );
	va_end( args );
	strcat( line, " # " );

	/* Add the date. ctime always attaches a '\n', gah.
	 */
	time( &timebuf );
	strcat( line, ctime( &timebuf ) );
	line[strlen( line ) - 1] = '\0';

#ifdef DEBUG
	printf( "im_histlin: adding:\n\t%s\nto history on image %p\n", 
		line, image );
#endif /*DEBUG*/

	image->history_list = g_slist_append( image->history_list, 
		im__gvalue_ref_string_new( line ) );

	return( 0 );
}

/**
 * vips_image_history_args:
 * @out: image to attach history line to
 * @name: program name
 * @argc: number of program arguments
 * @argv: program arguments
 *
 * Formats the name/argv as a single string and calls
 * vips_image_history_printf(). A
 * convenience function for command-line prorams.
 *
 * See also: vips_image_get_history().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_history_args( VipsImage *image, 
	const char *name, int argc, char *argv[] )
{	
	int i;
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );

	vips_buf_appends( &buf, name );

	for( i = 0; i < argc; i++ ) {
		vips_buf_appends( &buf, " " );
		vips_buf_appends( &buf, argv[i] );
	}

	if( vips_image_history_printf( image, "%s", vips_buf_all( &buf ) ) ) 
		return( -1 );

	return( 0 );
}

/**
 * vips_image_get_history:
 * @image: get history from here
 *
 * This function reads the image history as a C string. The string is owned
 * by VIPS and must not be freed.
 *
 * VIPS tracks the history of each image, that is, the sequence of operations
 * that generated that image. Applications built on VIPS need to call
 * vips_image_history_printf() for each action they perform, setting the 
 * command-line equivalent for the action.
 *
 * See also: vips_image_history_printf().
 *
 * Returns: The history of @image as a C string. Do not free!
 */
const char *
vips_image_get_history( VipsImage *image )
{
	if( !image->Hist )
		image->Hist = im__gslist_gvalue_get( image->history_list );

	return( image->Hist ? image->Hist : "" );
}
