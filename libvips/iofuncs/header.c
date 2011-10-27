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

/*
#define VIPS_DEBUG
#define DEBUG
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
#include <vips/debug.h>

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
 * Use vips_image_get_typeof() to test for the 
 * existance and #GType
 * of a header field.
 *
 * See <link linkend="libvips-meta">meta</link>
 * for a set of functions for adding new metadata to an image.
 */

/**
 * SECTION: meta
 * @short_description: get and set image metadata
 * @stability: Stable
 * @see_also: <link linkend="libvips-header">header</link>
 * @include: vips/vips.h
 *
 * You can attach arbitrary metadata to images. VipsMetadata is copied as images
 * are processed, so all images which used this image as input, directly or
 * indirectly, will have this same bit of metadata attached to them. Copying
 * is implemented with reference-counted pointers, so it is efficient, even for
 * large items of data. This does however mean that metadata items need to be
 * immutable. VipsMetadata
 * is handy for things like ICC profiles or EXIF data.
 *
 * Various convenience functions (eg. vips_image_set_int()) let you easily 
 * attach 
 * simple types like
 * numbers, strings and memory blocks to images. Use vips_image_map() to loop
 * over an image's fields, including all metadata.
 *
 * Items of metadata are identified by strings. Some strings are reserved, for
 * example the ICC profile for an image is known by convention as
 * "icc-profile-data".
 *
 * If you save an image in VIPS format, all metadata (with a restriction, see
 * below) is automatically saved for you in a block of XML at the end of the
 * file. When you load a VIPS image, the metadata is restored. You can use the
 * 'edvips' command-line tool to extract or replace this block of XML.
 *
 * VIPS metadata is based on GValue. See the docs for that system if you want
 * to do fancy stuff such as defining a new metadata type.
 * VIPS defines a new GValue called "vips_save_string", a variety of string. If 
 * your GValue can be transformed to vips_save_string, it will be saved and
 * loaded to and from VIPS files for you.
 *
 * VIPS provides a couple of base classes which implement
 * reference-counted areas of memory. If you base your metadata on one of
 * these types, it can be copied between images efficiently.
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
 * consistency with the vips_image_*() functions.
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

/* This is used by (eg.) VIPS_IMAGE_SIZEOF_ELEMENT() to calculate object
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

#ifdef DEBUG
/* Check that this meta is on the hash table.
 */
static void *
meta_sanity_on_hash( VipsMeta *meta, VipsImage *im )
{
	VipsMeta *found;

	if( meta->im != im )
		printf( "*** field \"%s\" has incorrect im\n", 
			meta->field );

	if( !(found = g_hash_table_lookup( im->meta, meta->field )) )
		printf( "*** field \"%s\" is on traverse but not in hash\n", 
			meta->field );

	if( found != meta )
		printf(  "*** meta \"%s\" on traverse and hash do not match\n", 
			meta->field );

	return( NULL );
}

static void
meta_sanity_on_traverse( const char *field, VipsMeta *meta, VipsImage *im )
{
	if( meta->field != field )
		printf( "*** field \"%s\" has incorrect field\n", 
			meta->field );

	if( meta->im != im )
		printf( "*** field \"%s\" has incorrect im\n", 
			meta->field );

	if( !g_slist_find( im->meta_traverse, meta ) )
		printf( "*** field \"%s\" is in hash but not on traverse\n", 
			meta->field );
}

static void
meta_sanity( const VipsImage *im )
{
	if( im->meta )
		g_hash_table_foreach( im->meta, 
			(GHFunc) meta_sanity_on_traverse, (void *) im );
	vips_slist_map2( im->meta_traverse, 
		(VipsSListMap2Fn) meta_sanity_on_hash, (void *) im, NULL );
}
#endif /*DEBUG*/

static void
meta_free( VipsMeta *meta )
{
#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents( &meta->value );
	printf( "meta_free: field %s, value = %s\n", 
		meta->field, str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	if( meta->im )
		meta->im->meta_traverse = 
			g_slist_remove( meta->im->meta_traverse, meta );

	g_value_unset( &meta->value );
	g_free( meta->field );
	g_free( meta );
}

static VipsMeta *
meta_new( VipsImage *image, const char *field, GValue *value )
{
	VipsMeta *meta;

	meta = g_new( VipsMeta, 1 );
	meta->im = image;
	meta->field = NULL;
	memset( &meta->value, 0, sizeof( GValue ) );
	meta->field = g_strdup( field );

	g_value_init( &meta->value, G_VALUE_TYPE( value ) );
	g_value_copy( value, &meta->value );

	image->meta_traverse = g_slist_append( image->meta_traverse, meta );
	g_hash_table_replace( image->meta, meta->field, meta ); 

#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "meta_new: field %s, value = %s\n", 
		field, str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	return( meta );
}

/* Destroy all the meta on an image.
 */
void
vips__meta_destroy( VipsImage *image )
{
	VIPS_FREEF( g_hash_table_destroy, image->meta );
	g_assert( !image->meta_traverse );
}

static void
meta_init( VipsImage *im )
{
	if( !im->meta ) {
		g_assert( !im->meta_traverse );
		im->meta = g_hash_table_new_full( g_str_hash, g_str_equal,
			NULL, (GDestroyNotify) meta_free );
	}
}

int
vips_image_get_width( const VipsImage *image )
{
	return( image->Xsize );
}

int
vips_image_get_height( const VipsImage *image )
{
	return( image->Ysize );
}

int
vips_image_get_bands( const VipsImage *image )
{
	return( image->Bands );
}

VipsBandFormat
vips_image_get_format( const VipsImage *image )
{
	return( image->BandFmt );
}

VipsCoding
vips_image_get_coding( const VipsImage *image )
{
	return( image->Coding );
}

VipsInterpretation
vips_image_get_interpretation( const VipsImage *image )
{
	return( image->Type );
}

double
vips_image_get_xres( const VipsImage *image )
{
	return( image->Xres );
}

double
vips_image_get_yres( const VipsImage *image )
{
	return( image->Yres );
}

int
vips_image_get_xoffset( const VipsImage *image )
{
	return( image->Xoffset );
}

int
vips_image_get_yoffset( const VipsImage *image )
{
	return( image->Yoffset );
}

const char *
vips_image_get_filename( const VipsImage *image )
{
	return( image->filename );
}

const char *
vips_image_get_mode( const VipsImage *image )
{
	return( image->mode );
}

/**
 * vips_image_get_data:
 * @image: image to get data for
 *
 * Return a pointer to the image's pixel data, if possible. This can involve
 * allocating large amounts of memory and performing a long computation. Image
 * pixels are laid out in band-packed rows.
 *
 * See also: vips_image_wio_input().
 *
 * Returns: a pointer to pixel data, if possible.
 */
void *
vips_image_get_data( VipsImage *image )
{
	if( vips_image_wio_input( image ) )
		return( NULL );

	return( image->data ); 
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

static void *
meta_cp_field( VipsMeta *meta, VipsImage *dst )
{
#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents( &meta->value );
	printf( "vips__meta_cp: copying field %s, value = %s\n", 
		meta->field, str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	(void) meta_new( dst, meta->field, &meta->value );

#ifdef DEBUG
	meta_sanity( dst );
#endif /*DEBUG*/

	return( NULL );
}

/* Copy meta on to dst. Called from vips_cp_desc().
 */
static int
meta_cp( VipsImage *dst, const VipsImage *src )
{
	if( src->meta ) {
		/* Loop, copying fields.
		 */
		meta_init( dst );
		vips_slist_map2( src->meta_traverse,
			(VipsSListMap2Fn) meta_cp_field, dst, NULL );
	}

	return( 0 );
}

/**
 * vips_image_copy_fields_array:
 * @out: image to copy to
 * @in: %NULL-terminated array of images to copy from
 *
 * Copy fields from all the input images to the output image. There must be at
 * least one input image. 
 *
 * The first input image is used to set the main fields of @out (@width,
 * @coding and so on). 
 *
 * Metadata from all the images is merged on to @out, with lower-numbered items 
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
	vips__meta_destroy( out );
	for( i = ni - 1; i >= 0; i-- ) 
		if( meta_cp( out, in[i] ) )
			return( -1 );

	/* Merge hists first to last.
	 */
	for( i = 0; in[i]; i++ )
		out->history_list = vips__gslist_gvalue_merge( 
			out->history_list, in[i]->history_list );

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
	for( i = 1; i < MAX_IMAGES && 
		(in[i] = va_arg( ap, VipsImage * )); i++ ) 
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		vips_error( "vips_image_copy_fieldsv", 
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
 * vips_image_set:
 * @image: image to set the metadata on
 * @field: the name to give the metadata
 * @value: the GValue to copy into the image
 *
 * Set a piece of metadata on @image. Any old metadata with that name is
 * destroyed. The GValue is copied into the image, so you need to unset the
 * value when you're done with it.
 *
 * For example, to set an integer on an image (though you would use the
 * convenience function vips_image_set_int() in practice), you would need:
 *
 * |[
 * GValue value = { 0 };
 *
 * g_value_init( &value, G_TYPE_INT );
 * g_value_set_int( &value, 42 );
 * vips_image_set( image, field, &value );
 * g_value_unset( &value );
 *
 * return( 0 );
 * ]|
 *
 * See also: vips_image_get().
 */
void
vips_image_set( VipsImage *image, const char *field, GValue *value )
{
	g_assert( field );
	g_assert( value );

	meta_init( image );
	(void) meta_new( image, field, value );

#ifdef DEBUG
	meta_sanity( image );
#endif /*DEBUG*/
}

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
 * does not exist. Use vips_image_get_typeof() to test for the 
 * existence
 * of a field first if you are not certain it will be there.
 *
 * For example, to read a double from an image (though of course you would use
 * vips_image_get_double() in practice):
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
	VipsMeta *meta;

	g_assert( field );
	g_assert( value_copy );

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

	if( image->meta && 
		(meta = g_hash_table_lookup( image->meta, field )) ) {
		g_value_init( value_copy, G_VALUE_TYPE( &meta->value ) );
		g_value_copy( &meta->value, value_copy );

		return( 0 );
	}

	vips_error( "vips_image_get", _( "field \"%s\" not found" ), field );

	return( -1 );
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
	VipsMeta *meta;

	g_assert( field );

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

	if( image->meta && 
		(meta = g_hash_table_lookup( image->meta, field )) ) 
		return( G_VALUE_TYPE( &meta->value ) );

	VIPS_DEBUG_MSG( "vips_image_get_typeof: unknown field %s\n", field );

	return( 0 );
}

/**
 * vips_image_remove:
 * @image: image to test
 * @field: the name to search for
 *
 * Find and remove an item of metadata. Return %FALSE if no metadata of that
 * name was found.
 *
 * See also: vips_image_set(), vips_image_get_typeof().
 *
 * Returns: %TRUE if an item of metadata of that name was found and removed
 */
gboolean
vips_image_remove( VipsImage *image, const char *field )
{
	if( image->meta && 
		g_hash_table_remove( image->meta, field ) )
		return( TRUE );

	return( FALSE );
}

static void *
vips_image_map_fn( VipsMeta *meta, VipsImageMapFn fn, void *a )
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

	if( image->meta_traverse && 
		(result = vips_slist_map2( image->meta_traverse, 
			(VipsSListMap2Fn) vips_image_map_fn, fn, a )) )
		return( result );

	return( NULL );
}

/* Save meta fields to the header. We have a new string type for header fields
 * to save to XML and define transform functions to go from our meta types to
 * this string type.
 */
GType
vips_save_string_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_save_string",
			(GBoxedCopyFunc) g_strdup, 
			(GBoxedFreeFunc) g_free );
	}

	return( type );
}

/** 
 * vips_save_string_get:
 * @value: GValue to get from
 *
 * Get the C string held internally by the GValue.
 *
 * Returns: The C string held by @value. This must not be freed.
 */
const char *
vips_save_string_get( const GValue *value )
{
	return( (char *) g_value_get_boxed( value ) );
}

/** 
 * vips_save_string_set:
 * @value: GValue to set
 * @str: C string to copy into the GValue
 *
 * Copies the C string into @value.
 */
void
vips_save_string_set( GValue *value, const char *str )
{
	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_SAVE_STRING );

	g_value_set_boxed( value, str );
}

/** 
 * vips_save_string_setf:
 * @value: GValue to set
 * @fmt: printf()-style format string
 * @Varargs: arguments to printf()-formatted @fmt
 *
 * Generates a string and copies it into @value.
 */
void
vips_save_string_setf( GValue *value, const char *fmt, ... )
{
	va_list ap;
	char *str;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_SAVE_STRING );

	va_start( ap, fmt );
	str = g_strdup_vprintf( fmt, ap );
	va_end( ap );
	vips_save_string_set( value, str );
	g_free( str );
}

/* Transform funcs for builtin types to SAVE_STRING.
 */
static void
transform_int_save_string( const GValue *src_value, GValue *dest_value )
{
	vips_save_string_setf( dest_value, "%d", g_value_get_int( src_value ) );
}

static void
transform_save_string_int( const GValue *src_value, GValue *dest_value )
{
	g_value_set_int( dest_value, 
		atoi( vips_save_string_get( src_value ) ) );
}

static void
transform_double_save_string( const GValue *src_value, GValue *dest_value )
{
	char buf[G_ASCII_DTOSTR_BUF_SIZE];

	/* Need to be locale independent.
	 */
	g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, 
		g_value_get_double( src_value ) );
	vips_save_string_set( dest_value, buf );
}

static void
transform_save_string_double( const GValue *src_value, GValue *dest_value )
{
	g_value_set_double( dest_value, 
		g_ascii_strtod( vips_save_string_get( src_value ), NULL ) );
}

#ifdef DEBUG
static int area_number = 0;
#endif /*DEBUG*/

/* An area of mem with a free func. (eg. \0-terminated string, or a struct).
 * Inital count == 1, so _unref() after attaching somewhere.
 */
static VipsArea *
area_new( VipsCallbackFn free_fn, void *data )
{
	VipsArea *area;

	if( !(area = VIPS_NEW( NULL, VipsArea )) )
		return( NULL );
	area->count = 1;
	area->length = 0;
	area->data = data;
	area->free_fn = free_fn;
	area->type = 0;
	area->sizeof_type = 0;

#ifdef DEBUG
	area_number += 1;
	printf( "area_new: %p count = %d (%d in total)\n", 
		area, area->count, area_number );
#endif /*DEBUG*/

	return( area );
}

/* An area of mem with a free func and a length (some sort of binary object,
 * like an ICC profile).
 */
static VipsArea *
area_new_blob( VipsCallbackFn free_fn, void *blob, size_t blob_length )
{
	VipsArea *area;

	if( !(area = area_new( free_fn, blob )) )
		return( NULL );
	area->length = blob_length;

	return( area );
}

/* An area which holds a copy of an array of elements of some GType.
 */
VipsArea *
vips_area_new_array( GType type, size_t sizeof_type, int n )
{
	VipsArea *area;
	void *array;

	array = g_malloc( n * sizeof_type );
	if( !(area = area_new( (VipsCallbackFn) g_free, array )) )
		return( NULL );
	area->n = n;
	area->length = n * sizeof_type;
	area->type = G_TYPE_DOUBLE;
	area->sizeof_type = sizeof_type;

	return( area );
}

VipsArea *
vips_area_copy( VipsArea *area )
{
	g_assert( area->count >= 0 );

	area->count += 1;

#ifdef DEBUG
	printf( "vips_area_copy: %p count = %d\n", area, area->count );
#endif /*DEBUG*/

	return( area );
}

void
vips_area_unref( VipsArea *area )
{
	g_assert( area->count > 0 );

	area->count -= 1;

#ifdef DEBUG
	printf( "vips_area_unref: %p count = %d\n", area, area->count );
#endif /*DEBUG*/

	if( area->count == 0 && area->free_fn ) {
		(void) area->free_fn( area->data, NULL );
		area->free_fn = NULL;
		vips_free( area );

#ifdef DEBUG
		area_number -= 1;
		printf( "vips_area_unref: free .. total = %d\n", area_number );
#endif /*DEBUG*/
	}
}

/* Transform an area to a G_TYPE_STRING.
 */
static void
transform_area_g_string( const GValue *src_value, GValue *dest_value )
{
	VipsArea *area;
	char buf[256];

	area = g_value_get_boxed( src_value );
	vips_snprintf( buf, 256, "VIPS_TYPE_AREA, count = %d, data = %p",
		area->count, area->data );
	g_value_set_string( dest_value, buf );
}

GType
vips_area_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_area",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( 
			type,
			G_TYPE_STRING,
			transform_area_g_string );
	}

	return( type );
}

/* Set value to be a ref-counted area of memory with a free function.
 */
static int
value_set_area( VipsCallbackFn free_fn, void *data, GValue *value )
{
	VipsArea *area;

	if( !(area = area_new( free_fn, data )) )
		return( -1 );

	g_value_init( value, VIPS_TYPE_AREA );
	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

/* Don't touch count (area is static).
 */
static void *
value_get_area_data( const GValue *value )
{
	VipsArea *area;

	area = g_value_get_boxed( value );

	return( area->data );
}

static size_t
value_get_area_length( const GValue *value )
{
	VipsArea *area;

	area = g_value_get_boxed( value );

	return( area->length );
}

static int
meta_get_value( VipsImage *image, 
	const char *field, GType type, GValue *value_copy )
{
	if( vips_image_get( image, field, value_copy ) )
		return( -1 );
	if( G_VALUE_TYPE( value_copy ) != type ) {
		vips_error( "VipsImage", 
			_( "field \"%s\" is of type %s, not %s" ),
			field, 
			g_type_name( G_VALUE_TYPE( value_copy ) ),
			g_type_name( type ) );
		g_value_unset( value_copy );
		return( -1 );
	}

	return( 0 );
}

/** 
 * vips_image_set_area:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @free_fn: free function for @data
 * @data: pointer to area of memory
 *
 * Attaches @data as a metadata item on @image under the name @field. When VIPS
 * no longer needs the metadata, it will be freed with @free_fn.
 *
 * See also: vips_image_get_double(), vips_image_set()
 */
void
vips_image_set_area( VipsImage *image, const char *field, 
	VipsCallbackFn free_fn, void *data )
{
	GValue value = { 0 };

	value_set_area( free_fn, data, &value );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
}

/** 
 * vips_image_get_area:
 * @image: image to get the metadata from
 * @field: metadata name
 * @data: return metadata value
 *
 * Gets @data from @image under the name @field. A convenience
 * function over vips_image_get(). Use vips_image_get_typeof() to test for the 
 * existance
 * of a piece of metadata.
 *
 * See also: vips_image_set_area(), vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_area( VipsImage *image, const char *field, void **data )
{
	GValue value_copy = { 0 };

	if( !meta_get_value( image, field, VIPS_TYPE_AREA, &value_copy ) ) {
		*data = value_get_area_data( &value_copy );
		g_value_unset( &value_copy );
		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_ref_string_get:
 * @value: GValue to get from
 *
 * Get the C string held internally by the GValue.
 *
 * Returns: The C string held by @value. This must not be freed.
 */
const char *
vips_ref_string_get( const GValue *value )
{
	return( value_get_area_data( value ) );
}

/** 
 * vips_ref_string_get_length:
 * @value: GValue to get from
 *
 * Gets the cached string length held internally by the refstring.
 *
 * Returns: The length of the string.
 */
size_t
vips_ref_string_get_length( const GValue *value )
{
	return( value_get_area_length( value ) );
}

/** 
 * vips_ref_string_set:
 * @value: GValue to set
 * @str: C string to copy into the GValue
 *
 * Copies the C string @str into @value. 
 *
 * vips_ref_string are immutable C strings that are copied between images by
 * copying reference-counted pointers, making the much more efficient than
 * regular GValue strings.
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_ref_string_set( GValue *value, const char *str )
{
	VipsArea *area;
	char *str_copy;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_REF_STRING );

	str_copy = g_strdup( str );
	if( !(area = area_new( (VipsCallbackFn) vips_free, str_copy )) ) {
		g_free( str_copy );
		return( -1 );
	}

	/* Handy place to cache this.
	 */
	area->length = strlen( str );

	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

/* Transform a refstring to a G_TYPE_STRING and back.
 */
static void
transform_ref_string_g_string( const GValue *src_value, GValue *dest_value )
{
	g_value_set_string( dest_value, vips_ref_string_get( src_value ) );
}

static void
transform_g_string_ref_string( const GValue *src_value, GValue *dest_value )
{
	vips_ref_string_set( dest_value, g_value_get_string( src_value ) );
}

/* To a save string.
 */
static void
transform_ref_string_save_string( const GValue *src_value, GValue *dest_value )
{
	vips_save_string_setf( dest_value, 
		"%s", vips_ref_string_get( src_value ) );
}

static void
transform_save_string_ref_string( const GValue *src_value, GValue *dest_value )
{
	vips_ref_string_set( dest_value, vips_save_string_get( src_value ) );
}

GType
vips_ref_string_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_ref_string",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_ref_string_g_string );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_ref_string );
		g_value_register_transform_func( type, VIPS_TYPE_SAVE_STRING,
			transform_ref_string_save_string );
		g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, type,
			transform_save_string_ref_string );
	}

	return( type );
}

/** 
 * vips_blob_get:
 * @value: GValue to get from
 * @length: return the blob length here, optionally
 *
 * Get the address of the blob (binary large object) being held in @value and
 * optionally return its length in @length.
 *
 * See also: vips_blob_set().
 *
 * Returns: The blob address.
 */
void *
vips_blob_get( const GValue *value, size_t *length )
{
	VipsArea *area;

	/* Can't check value type, because we may get called from
	 * vips_blob_get_type().
	 */

	area = g_value_get_boxed( value );
	if( length )
		*length = area->length;

	return( area->data );
}

/* Transform a blob to a G_TYPE_STRING.
 */
static void
transform_blob_g_string( const GValue *src_value, GValue *dest_value )
{
	void *blob;
	size_t blob_length;
	char buf[256];

	blob = vips_blob_get( src_value, &blob_length );
	vips_snprintf( buf, 256, "VIPS_TYPE_BLOB, data = %p, length = %zd",
		blob, blob_length );
	g_value_set_string( dest_value, buf );
}

/* Transform a blob to a save string and back.
 */
static void
transform_blob_save_string( const GValue *src_value, GValue *dest_value )
{
	void *blob;
	size_t blob_length;
	char *b64;

	blob = vips_blob_get( src_value, &blob_length );
	if( (b64 = vips__b64_encode( blob, blob_length )) ) {
		vips_save_string_set( dest_value, b64 );
		vips_free( b64 );
	}
}

static void
transform_save_string_blob( const GValue *src_value, GValue *dest_value )
{
	const char *b64;
	void *blob;
	size_t blob_length;

	b64 = vips_save_string_get( src_value );
	if( (blob = vips__b64_decode( b64, &blob_length )) )
		vips_blob_set( dest_value, 
			(VipsCallbackFn) vips_free, blob, blob_length );
}

GType
vips_blob_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_blob",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_blob_g_string );
		g_value_register_transform_func( type, VIPS_TYPE_SAVE_STRING,
			transform_blob_save_string );
		g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, type,
			transform_save_string_blob );
	}

	return( type );
}

/** 
 * vips_blob_set:
 * @value: GValue to set
 * @free_fn: free function for @data
 * @data: pointer to area of memory
 * @length: length of memory area
 *
 * Sets @value to hold a pointer to @blob. When @value is freed, @blob will be
 * freed with @free_fn. @value also holds a note of the length of the memory
 * area.
 *
 * blobs are things like ICC profiles or EXIF data. They are relocatable, and
 * are saved to VIPS files for you coded as base64 inside the XML. They are
 * copied by copying reference-counted pointers.
 *
 * See also: vips_blob_get()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_blob_set( GValue *value, 
	VipsCallbackFn free_fn, void *data, size_t length ) 
{
	VipsArea *area;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_BLOB );

	if( !(area = area_new_blob( free_fn, data, length )) )
		return( -1 );

	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

/* Set value to be an array of things. Don't initialise the contents: get the
 * pointer and write instead.
 */
static int
vips_array_set( GValue *value, GType type, size_t sizeof_type, int n )
{
	VipsArea *area;

	if( !(area = vips_area_new_array( type, sizeof_type, n )) )
		return( -1 );
	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

static void *
vips_array_get( const GValue *value, 
	int *n, GType *type, size_t *sizeof_type )
{
	VipsArea *area;

	/* Can't check value type, because we may get called from
	 * vips_*_get_type().
	 */

	area = g_value_get_boxed( value );
	if( n )
		*n = area->n;
	if( type )
		*type = area->type;
	if( sizeof_type )
		*sizeof_type = area->sizeof_type;

	return( area->data );
}

static void
transform_array_g_string( const GValue *src_value, GValue *dest_value )
{
	char *array;
	int n;
	GType type;
	size_t sizeof_type;
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int i;

	array = (char *) vips_array_get( src_value, 
		&n, &type, &sizeof_type );

	for( i = 0; i < n; i++ ) {
		GValue value = { 0, };
		char *str;

		if( i > 0 )
			vips_buf_appends( &buf, ", " );

		g_value_init( &value, type );
		g_value_set_instance( &value, array );

		str = g_strdup_value_contents( &value );
		vips_buf_appends( &buf, str );
		g_free( str );

		g_value_unset( &value );

		array += sizeof_type;
	}

	g_value_set_string( dest_value, vips_buf_all( &buf ) );
}

/* It'd be great to be able to write a generic string->array function, but
 * it doesn't seem possible.
 */
static void
transform_g_string_array_double( const GValue *src_value, GValue *dest_value )
{
	const char *str = g_value_get_string( src_value );

	int n;
	const char *p;
	int i;
	double *array;

	/* Walk the string to get the number of elements. Empty string is zero
	 * elements.
	 */
	for( n = 0, p = str; p && *p; n += 1 ) {
		p = strchr( p, ',' );
		if( p )
			p += 1;
	}

	vips_array_set( dest_value, G_TYPE_DOUBLE, sizeof( double ), n );
	array = (double *) vips_array_get( dest_value, NULL, NULL, NULL );

	p = str;
	for( i = 0; i < n; i++ ) {
		array[i] = atof( p );
		p = strchr( p, ',' );
		if( p )
			p += 1;
	}
}

GType
vips_array_double_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_array_double",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_array_g_string );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_array_double );
	}

	return( type );
}

/** 
 * vips_array_double_get:
 * @value: #GValue to get from
 * @n: return the number of elements here, optionally
 *
 * Return the start of the array of doubles held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_array_double_set().
 *
 * Returns: The array address.
 */
double *
vips_array_double_get( const GValue *value, int *n )
{
	return( vips_array_get( value, n, NULL, NULL ) );
}

/** 
 * vips_array_double_set:
 * @value: #GValue to get from
 * @array: array of doubles
 * @n: the number of elements 
 *
 * Set @value to hold a copy of @array. Pass in the array length in @n. 
 *
 * See also: vips_array_double_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_array_double_set( GValue *value, const double *array, int n )
{
	double *array_copy;

	g_value_init( value, VIPS_TYPE_ARRAY_DOUBLE );
	vips_array_set( value, G_TYPE_DOUBLE, sizeof( double ), n );
	array_copy = vips_array_double_get( value, NULL );
	memcpy( array_copy, array, n * sizeof( double ) );

	return( 0 );
}

static void
vips_array_object_free( VipsArea *area )
{
	GObject **array = (GObject **) area->data;

	int i;

	for( i = 0; i < area->n; i++ )
		VIPS_FREEF( g_object_unref, array[i] );

	g_free( area );
}

/* An area which holds an array of GObjects.
 */
VipsArea *
vips_array_object_new( int n )
{
	GObject **array;
	VipsArea *area;

	array = g_new0( GObject *, n );
	if( !(area = area_new( 
		(VipsCallbackFn) vips_array_object_free, array )) )
		return( NULL );
	area->n = n;
	area->length = n * sizeof( GObject * );
	area->type = G_TYPE_OBJECT;
	area->sizeof_type = sizeof( GObject * );

	return( area );
}

/** 
 * vips_array_object_get:
 * @value: #GValue to get from
 * @n: return the number of elements here, optionally
 *
 * Return the start of the array of #GObject held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_array_object_set().
 *
 * Returns: The array address.
 */
GObject **
vips_array_object_get( const GValue *value, int *n )
{
	return( vips_array_get( value, n, NULL, NULL ) );
}

/** 
 * vips_array_object_set:
 * @value: #GValue to set
 * @n: the number of elements 
 *
 * Set @value to hold an array of GObject. Pass in the array length in @n. 
 *
 * See also: vips_array_object_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_array_object_set( GValue *value, int n )
{
	VipsArea *area;

	if( !(area = vips_array_object_new( n )) )
		return( -1 );
	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

static void
transform_g_string_array_image( const GValue *src_value, GValue *dest_value )
{
	char *str;
	int n;
	char *p, *q;
	int i;
	GObject **array;

	/* We need a copy of the string, since we insert \0 during
	 * scan.
	 */
	str = g_strdup_value_contents( src_value );
	for( n = 0; (q = vips_break_token( p, " " )); n++, p = q )
		;
	g_free( str );

	vips_array_object_set( dest_value, n );
	array = vips_array_object_get( dest_value, NULL );

	str = g_strdup_value_contents( src_value );
	for( i = 0; (q = vips_break_token( p, " " )); i++, p = q )
		/* Sadly there's no error return possible here.
		 */
		array[i] = G_OBJECT( vips_image_new_from_file( p ) );
	g_free( str );
}

GType
vips_array_image_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "vips_array_image",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_array_image );
	}

	return( type );
}

/** 
 * vips_image_set_blob:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @free_fn: free function for @data
 * @data: pointer to area of memory
 * @length: length of memory area
 *
 * Attaches @blob as a metadata item on @image under the name @field. A 
 * convenience
 * function over vips_image_set() using an vips_blob.
 *
 * See also: vips_image_get_blob(), vips_image_set().
 */
void
vips_image_set_blob( VipsImage *image, const char *field, 
	VipsCallbackFn free_fn, void *data, size_t length )
{
	GValue value = { 0 };

	g_value_init( &value, VIPS_TYPE_BLOB );
	vips_blob_set( &value, free_fn, data, length );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
}

/** 
 * vips_image_get_blob:
 * @image: image to get the metadata from
 * @field: metadata name
 * @data: pointer to area of memory
 * @length: return the blob length here, optionally
 *
 * Gets @blob from @image under the name @field, optionally return its length in
 * @length. A convenience
 * function over vips_image_get(). Use vips_image_get_typeof() to test for the 
 * existance
 * of a piece of metadata.
 *
 * See also: vips_image_get(), vips_image_get_typeof(), vips_blob_get(), 
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_blob( VipsImage *image, const char *field, 
	void **data, size_t *length )
{
	GValue value_copy = { 0 };

	if( !meta_get_value( image, field, VIPS_TYPE_BLOB, &value_copy ) ) {
		*data = vips_blob_get( &value_copy, length );
		g_value_unset( &value_copy );
		return( 0 );
	}

	return( -1 );
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
	GValue value_copy = { 0 };

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

	if( !meta_get_value( image, field, G_TYPE_INT, &value_copy ) ) {
		*out = g_value_get_int( &value_copy );
		g_value_unset( &value_copy );

		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_set_int:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @i: metadata value
 *
 * Attaches @i as a metadata item on @image under the name @field. A 
 * convenience
 * function over vips_image_set().
 *
 * See also: vips_image_get_int(), vips_image_set()
 */
void
vips_image_set_int( VipsImage *image, const char *field, int i )
{
	GValue value = { 0 };

	g_value_init( &value, G_TYPE_INT );
	g_value_set_int( &value, i );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
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
	GValue value_copy = { 0 };

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


	if( !meta_get_value( image, field, G_TYPE_DOUBLE, &value_copy ) ) {
		*out = g_value_get_double( &value_copy );
		g_value_unset( &value_copy );

		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_set_double:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @d: metadata value
 *
 * Attaches @d as a metadata item on @image under the name @field. A 
 * convenience
 * function over vips_image_set().
 *
 * See also: vips_image_get_double(), vips_image_set()
 */
void
vips_image_set_double( VipsImage *image, const char *field, double d )
{
	GValue value = { 0 };

	g_value_init( &value, G_TYPE_DOUBLE );
	g_value_set_double( &value, d );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
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
	GValue value_copy = { 0 };
	VipsArea *area;

	for( i = 0; i < VIPS_NUMBER( string_field ); i++ )
		if( strcmp( field, string_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( char *, image, 
				string_field[i].offset );
			return( 0 );
		}

	if( !meta_get_value( image, 
		field, VIPS_TYPE_REF_STRING, &value_copy ) ) {
		area = g_value_get_boxed( &value_copy );
		*out = area->data;
		g_value_unset( &value_copy );

		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_set_string:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @str: metadata value
 *
 * Attaches @str as a metadata item on @image under the name @field. 
 * A convenience
 * function over vips_image_set() using an vips_ref_string.
 *
 * See also: vips_image_get_double(), vips_image_set(), vips_ref_string
 */
void
vips_image_set_string( VipsImage *image, const char *field, const char *str )
{
	GValue value = { 0 };

	g_value_init( &value, VIPS_TYPE_REF_STRING );
	vips_ref_string_set( &value, str );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
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
	if( g_value_type_transformable( type, VIPS_TYPE_SAVE_STRING ) ) {
		GValue save_value = { 0 };

		g_value_init( &save_value, VIPS_TYPE_SAVE_STRING );
		if( !g_value_transform( &value, &save_value ) ) 
			return( -1 );
		*out = g_strdup( vips_save_string_get( &save_value ) );
		g_value_unset( &save_value );
	}
	else 
		*out = g_strdup_value_contents( &value );

	g_value_unset( &value );

	return( 0 );
}

/**
 * vips_image_history_printf:
 * @image: add history line to this image
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
	(void) vips_vsnprintf( line, 4096 - 40, fmt, args );
	va_end( args );
	strcat( line, " # " );

	/* Add the date. ctime always attaches a '\n', gah.
	 */
	time( &timebuf );
	strcat( line, ctime( &timebuf ) );
	line[strlen( line ) - 1] = '\0';

#ifdef DEBUG
	printf( "vips_image_history_printf: "
		"adding:\n\t%s\nto history on image %p\n", line, image );
#endif /*DEBUG*/

	image->history_list = g_slist_append( image->history_list, 
		vips__gvalue_ref_string_new( line ) );

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
		image->Hist = vips__gslist_gvalue_get( image->history_list );

	return( image->Hist ? image->Hist : "" );
}

/* Make the types we need for basic functioning. Called from init_world().
 */
void
vips__meta_init_types( void )
{
	(void) vips_save_string_get_type();
	(void) vips_area_get_type();
	(void) vips_ref_string_get_type();
	(void) vips_blob_get_type();

	/* Register transform functions to go from built-in saveable types to 
	 * a save string. Transform functions for our own types are set 
	 * during type creation. 
	 */
	g_value_register_transform_func( G_TYPE_INT, VIPS_TYPE_SAVE_STRING,
		transform_int_save_string );
	g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, G_TYPE_INT,
		transform_save_string_int );
	g_value_register_transform_func( G_TYPE_DOUBLE, VIPS_TYPE_SAVE_STRING,
		transform_double_save_string );
	g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, G_TYPE_DOUBLE,
		transform_save_string_double );
}
