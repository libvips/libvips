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
 *
 * It needs to be guint64 and not size_t since we use this as the basis for 
 * image address calcs and they have to be 64-bit, even on 32-bit machines. 
 */
const guint64 vips__image_sizeof_bandformat[] = {
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
guint64 
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

/* vips_image_get_interpretation:
 * @image: image to guess for
 *
 * Return the #VipsInterpretation set in the image header.
 * Use vips_image_guess_interpretation() is you want a sanity-checked value.
 *
 * Returns: the #VipsInterpretation from the image header.
 */
VipsInterpretation
vips_image_get_interpretation( const VipsImage *image )
{
	return( image->Type );
}

/* Try to pick a sane value for interpretation, assuming Type has been set
 * incorrectly.
 */
static VipsInterpretation
vips_image_default_interpretation( const VipsImage *image )
{
	switch( image->Coding ) {
	case VIPS_CODING_LABQ:
		return( VIPS_INTERPRETATION_LABQ );
	case VIPS_CODING_RAD:
		return( VIPS_INTERPRETATION_RGB );
	default:
		break;
	}

	if( image->Bands == 1 )
		return( VIPS_INTERPRETATION_B_W );
	else
		return( VIPS_INTERPRETATION_MULTIBAND );
}

/* vips_image_guess_interpretation:
 * @image: image to guess for
 *
 * Return the #VipsInterpretation for an image, guessing a default value if
 * the set value looks wrong.
 *
 * Returns: a sensible #VipsInterpretation for the image.
 */
VipsInterpretation
vips_image_guess_interpretation( const VipsImage *image )
{
	gboolean sane;

	sane = TRUE;
	switch( image->Type ) {

	case VIPS_INTERPRETATION_MULTIBAND: 
		if( image->Bands == 1 )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_B_W: 
		if( image->Bands > 1 )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_HISTOGRAM: 
		if( image->Xsize > 1 && image->Ysize > 1 )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_FOURIER: 
		if( !vips_band_format_iscomplex( image->BandFmt ) )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_XYZ: 
	case VIPS_INTERPRETATION_LAB: 
	case VIPS_INTERPRETATION_RGB: 
	case VIPS_INTERPRETATION_CMC: 
	case VIPS_INTERPRETATION_LCH: 
	case VIPS_INTERPRETATION_sRGB: 
	case VIPS_INTERPRETATION_YXY: 
		if( image->Bands < 3 )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_CMYK: 
		if( image->Bands < 4 )
			sane = FALSE;
		break;

	case  VIPS_INTERPRETATION_LABQ:
		if( image->Coding != VIPS_CODING_LABQ )
			sane = FALSE;
		break;

	case  VIPS_INTERPRETATION_LABS:
		if( image->BandFmt != VIPS_FORMAT_SHORT )
			sane = FALSE;
		break;

	case  VIPS_INTERPRETATION_RGB16:
		if( image->BandFmt == VIPS_FORMAT_CHAR ||
			image->BandFmt == VIPS_FORMAT_UCHAR ||
			image->Bands < 3 )
			sane = FALSE;
		break;

	case  VIPS_INTERPRETATION_GREY16:
		if( image->BandFmt == VIPS_FORMAT_CHAR ||
			image->BandFmt == VIPS_FORMAT_UCHAR )
			sane = FALSE;
		break;

	case  VIPS_INTERPRETATION_ARRAY:
		if( image->Bands != 1 )
			sane = FALSE;
		break;
	
	default:
		g_assert( 0 );
		sane = FALSE;
		break;
	}

	if( sane )
		return( vips_image_get_interpretation( image ) );
	else
		return( vips_image_default_interpretation( image ) );
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
 * vips_image_get_data: (skip)
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
 * @format: band format
 * @coding: image coding
 * @interpretation: image type
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
	double xres, double yres )
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

	/* Copy magic too, handy for knowing the original image's byte order.
	 */
	out->magic = in[0]->magic;

	out->Xsize = in[0]->Xsize;
	out->Ysize = in[0]->Ysize;
	out->Bands = in[0]->Bands;
	out->Bbits = in[0]->Bbits;
	out->BandFmt = in[0]->BandFmt;
	out->Type = in[0]->Type;
	out->Coding = in[0]->Coding;
	out->Xres = in[0]->Xres;
	out->Yres = in[0]->Yres;
	out->Xoffset = in[0]->Xoffset;
	out->Yoffset = in[0]->Yoffset;

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
				G_STRUCT_MEMBER( double, image, 
					double_field[i].offset ) );
			return( 0 );
		}

	for( i = 0; i < VIPS_NUMBER( old_double_field ); i++ ) 
		if( strcmp( field, old_double_field[i].field ) == 0 ) {
			g_value_init( value_copy, G_TYPE_DOUBLE );
			g_value_set_double( value_copy, 
				G_STRUCT_MEMBER( double, image, 
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
 * vips_image_map: (skip)
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

/**
 * vips_image_set_area:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @free_fn: (scope async): free function for @data
 * @data: pointer to area of memory
 *
 * Attaches @data as a metadata item on @image under the name @field. When
 * VIPS no longer needs the metadata, it will be freed with @free_fn.
 *
 * See also: vips_image_get_double(), vips_image_set()
 */
void
vips_image_set_area( VipsImage *image, const char *field,
		VipsCallbackFn free_fn, void *data )
{
	GValue value = { 0 };

	vips_value_set_area( &value, free_fn, data );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
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
 * vips_image_get_area:
 * @image: image to get the metadata from
 * @field: metadata name
 * @data: return metadata value
 *
 * Gets @data from @image under the name @field. A convenience
 * function over vips_image_get(). Use vips_image_get_typeof() to test for
 * the existance of a piece of metadata.
 *
 * See also: vips_image_set_area(), vips_image_get(),
 * vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_area( VipsImage *image, const char *field, void **data )
{
	GValue value_copy = { 0 };

	if( !meta_get_value( image, field, VIPS_TYPE_AREA, &value_copy ) ) {
		*data = vips_value_get_area( &value_copy, NULL );
		g_value_unset( &value_copy );
		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_set_blob:
 * @image: image to attach the metadata to
 * @field: metadata name
 * @free_fn: (scope async): free function for @data
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
	vips_value_set_blob( &value, free_fn, data, length );
	vips_image_set( image, field, &value );
	g_value_unset( &value );
}

/** 
 * vips_image_get_blob: (skip)
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
		*data = vips_value_get_blob( &value_copy, length );
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
			*out = G_STRUCT_MEMBER( double, image, 
				double_field[i].offset );
			return( 0 );
		}
	for( i = 0; i < VIPS_NUMBER( old_double_field ); i++ )
		if( strcmp( field, old_double_field[i].field ) == 0 ) {
			*out = G_STRUCT_MEMBER( double, image, 
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
	vips_value_set_ref_string( &value, str );
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
		*out = g_strdup( vips_value_get_save_string( &save_value ) );
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
 * @image: image to attach history line to
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
