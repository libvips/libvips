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
 * 16/7/15
 * 	- auto wrap GString as RefString
 * 20/10/16
 * 	- return header enums as enums, not ints
 * 	- vips_image_get_*() all convert everything to target type if they can
 * 	- rename "field" as "name" in docs
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
 * @see_also: <link linkend="libvips-type">type</link>
 * @include: vips/vips.h
 *
 * These functions let you get at image header data (including metadata) in a
 * uniform way. 
 *
 * Use vips_image_get_typeof() to test for the 
 * existance and #GType
 * of a header field.
 *
 * You can attach arbitrary metadata to images. Metadata is copied as images
 * are processed, so all images which used this image as input, directly or
 * indirectly, will have this same bit of metadata attached to them. Copying
 * is implemented with reference-counted pointers, so it is efficient, even for
 * large items of data. This does however mean that metadata items need to be
 * immutable. Metadata is handy for things like ICC profiles or EXIF data.
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
 * `vipsedit` command-line tool to extract or replace this block of XML.
 *
 * VIPS metadata is based on %GValue. See the docs for that system if you want
 * to do fancy stuff such as defining a new metadata type.
 * VIPS defines a new %GValue called `vips_save_string`, a variety of string,
 * see vips_value_set_save_string(). 
 * If your %GValue can be transformed to `vips_save_string`, it will be 
 * saved and loaded to and from VIPS files for you.
 *
 * VIPS provides a couple of base classes which implement
 * reference-counted areas of memory. If you base your metadata on one of
 * these types, it can be copied between images efficiently.
 */

/* We have to keep the gtype as a string, since we statically init this.
 */
typedef struct _HeaderField {
	const char *name;
	const char *type;
	glong offset;
} HeaderField;

/* Built in fields and struct offsets.
 */
static HeaderField vips_header_fields[] = {
	{ "width", "gint", G_STRUCT_OFFSET( VipsImage, Xsize ) },
	{ "height", "gint", G_STRUCT_OFFSET( VipsImage, Ysize ) },
	{ "bands", "gint", G_STRUCT_OFFSET( VipsImage, Bands ) },
	{ "format", "VipsBandFormat", G_STRUCT_OFFSET( VipsImage, BandFmt ) },
	{ "coding", "VipsCoding", G_STRUCT_OFFSET( VipsImage, Coding ) },
	{ "interpretation", "VipsInterpretation", 
		G_STRUCT_OFFSET( VipsImage, Type ) },
	{ "xoffset", "gint", G_STRUCT_OFFSET( VipsImage, Xoffset ) },
	{ "yoffset", "gint", G_STRUCT_OFFSET( VipsImage, Yoffset ) },
	{ "xres", "gdouble", G_STRUCT_OFFSET( VipsImage, Xres ) },
	{ "yres", "gdouble", G_STRUCT_OFFSET( VipsImage, Yres ) },
	{ "filename", "gchararray", G_STRUCT_OFFSET( VipsImage, filename ) }
};

/* Old names we keep around for back-compat. We never loop over these with
 * map, but we do check them when we look up fields by name.
 */
static HeaderField vips_header_fields_old[] = {
	{ "Xsize", "gint", G_STRUCT_OFFSET( VipsImage, Xsize ) },
	{ "Ysize", "gint", G_STRUCT_OFFSET( VipsImage, Ysize ) },
	{ "Bands", "gint", G_STRUCT_OFFSET( VipsImage, Bands ) },
	{ "Bbits", "gint", G_STRUCT_OFFSET( VipsImage, Bbits ) },
	{ "BandFmt", "gint", G_STRUCT_OFFSET( VipsImage, BandFmt ) },
	{ "Coding", "gint", G_STRUCT_OFFSET( VipsImage, Coding ) },
	{ "Type", "gint", G_STRUCT_OFFSET( VipsImage, Type ) },
	{ "Xoffset", "gint", G_STRUCT_OFFSET( VipsImage, Xoffset ) },
	{ "Yoffset", "gint", G_STRUCT_OFFSET( VipsImage, Yoffset ) },
	{ "Xres", "gdouble", G_STRUCT_OFFSET( VipsImage, Xres ) },
	{ "Yres", "gdouble", G_STRUCT_OFFSET( VipsImage, Yres ) }
};

/* This is used by (eg.) VIPS_IMAGE_SIZEOF_ELEMENT() to calculate object
 * size via vips_format_sizeof(). 
 *
 * It needs to be guint64 and not size_t since we use this as the basis for 
 * image address calcs and they have to be 64-bit, even on 32-bit machines. 
 *
 * Can't be static, we need this to be visible for vips7 compat.
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

/**
 * vips_format_sizeof:
 * @format: format type
 *
 * Returns: number of bytes for a band format.
 */
guint64 
vips_format_sizeof( VipsBandFormat format )
{
	format = VIPS_CLIP( 0, format, VIPS_FORMAT_DPCOMPLEX ); 

	return( vips__image_sizeof_bandformat[format] );
}

/**
 * vips_format_sizeof_unsafe: (skip)
 * @format: format type
 *
 * A fast but dangerous version of vips_format_sizeof(). You must have
 * previously range-checked @format or you'll crash.
 *
 * Returns: number of bytes for a band format.
 */
guint64 
vips_format_sizeof_unsafe( VipsBandFormat format )
{
	g_assert( 0 <= format && format <= VIPS_FORMAT_DPCOMPLEX ); 

	return( vips__image_sizeof_bandformat[format] );
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
			meta->name );

	if( !(found = g_hash_table_lookup( im->meta, meta->name )) )
		printf( "*** field \"%s\" is on traverse but not in hash\n", 
			meta->name );

	if( found != meta )
		printf(  "*** meta \"%s\" on traverse and hash do not match\n", 
			meta->name );

	return( NULL );
}

static void
meta_sanity_on_traverse( const char *name, VipsMeta *meta, VipsImage *im )
{
	if( meta->name != name )
		printf( "*** field \"%s\" has incorrect name\n", 
			meta->name );

	if( meta->im != im )
		printf( "*** field \"%s\" has incorrect im\n", 
			meta->name );

	if( !g_slist_find( im->meta_traverse, meta ) )
		printf( "*** field \"%s\" is in hash but not on traverse\n", 
			meta->name );
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
	printf( "meta_free: name %s, value = %s\n", 
		meta->name, str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	if( meta->im )
		meta->im->meta_traverse = 
			g_slist_remove( meta->im->meta_traverse, meta );

	g_value_unset( &meta->value );
	g_free( meta->name );
	g_free( meta );
}

static VipsMeta *
meta_new( VipsImage *image, const char *name, GValue *value )
{
	VipsMeta *meta;

	meta = g_new( VipsMeta, 1 );
	meta->im = image;
	meta->name = NULL;
	memset( &meta->value, 0, sizeof( GValue ) );
	meta->name = g_strdup( name );

	/* Special case: we don't want to have G_STRING on meta. They will be
	 * copied down pipelines, plus some of our API (like
	 * vips_image_get_string()) assumes that the GValue is a refstring and
	 * that read-only pointers can be handed out.
	 *
	 * Turn G_TYPE_STRING into VIPS_TYPE_REF_STRING.
	 */
	if( G_VALUE_TYPE( value ) == G_TYPE_STRING )
		g_value_init( &meta->value, VIPS_TYPE_REF_STRING );
	else
		g_value_init( &meta->value, G_VALUE_TYPE( value ) );

	/* We don't do any conversions that can fail.
	 */
	(void) g_value_transform( value, &meta->value );

	image->meta_traverse = g_slist_append( image->meta_traverse, meta );
	g_hash_table_replace( image->meta, meta->name, meta ); 

#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "meta_new: name %s, value = %s\n", name, str_value );
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

/**
 * vips_image_get_width:
 * @image: image to get from
 *
 * Returns: the number of pixels across the image.
 */
int
vips_image_get_width( const VipsImage *image )
{
	return( image->Xsize );
}

/**
 * vips_image_get_height:
 * @image: image to get from
 *
 * Returns: the number of pixels down the image.
 */
int
vips_image_get_height( const VipsImage *image )
{
	return( image->Ysize );
}

/**
 * vips_image_get_bands:
 * @image: image to get from
 *
 * Returns: the number of bands (channels) in the image.
 */
int
vips_image_get_bands( const VipsImage *image )
{
	return( image->Bands );
}

/**
 * vips_image_get_format:
 * @image: image to get from
 *
 * Returns: the format of each band element.
 */
VipsBandFormat
vips_image_get_format( const VipsImage *image )
{
	return( image->BandFmt );
}

/**
 * vips_image_guess_format:
 * @image: image to guess for
 *
 * Return the #VipsBandFormat for an image, guessing a sane value if
 * the set value looks crazy.
 *
 * For example, for a float image tagged as rgb16, we'd return ushort. 
 *
 * Returns: a sensible #VipsBandFormat for the image.
 */
VipsBandFormat
vips_image_guess_format( const VipsImage *image )
{
	VipsBandFormat format;

	/* Stop a compiler warning.
	 */
	format = VIPS_FORMAT_UCHAR; 

	switch( image->Type ) {
	case VIPS_INTERPRETATION_B_W: 
	case VIPS_INTERPRETATION_HISTOGRAM: 
	case VIPS_INTERPRETATION_MULTIBAND: 
		format = image->BandFmt;
		break;

	case VIPS_INTERPRETATION_FOURIER: 
		if( image->BandFmt == VIPS_FORMAT_DOUBLE ||
			image->BandFmt == VIPS_FORMAT_DPCOMPLEX )
			format = VIPS_FORMAT_DPCOMPLEX;
		else
			format = VIPS_FORMAT_COMPLEX;
		break;

	case VIPS_INTERPRETATION_sRGB: 
		format = VIPS_FORMAT_UCHAR;
		break;

	case VIPS_INTERPRETATION_XYZ: 
	case VIPS_INTERPRETATION_LAB: 
	case VIPS_INTERPRETATION_RGB: 
	case VIPS_INTERPRETATION_CMC: 
	case VIPS_INTERPRETATION_LCH: 
	case VIPS_INTERPRETATION_HSV: 
	case VIPS_INTERPRETATION_scRGB: 
	case VIPS_INTERPRETATION_YXY: 
		format = VIPS_FORMAT_FLOAT;
		break;

	case VIPS_INTERPRETATION_CMYK: 
		if( image->BandFmt == VIPS_FORMAT_USHORT )
			format = VIPS_FORMAT_USHORT;
		else
			format = VIPS_FORMAT_UCHAR;
		break;

	case  VIPS_INTERPRETATION_LABQ:
		format = VIPS_FORMAT_UCHAR;
		break;

	case  VIPS_INTERPRETATION_LABS:
		format = VIPS_FORMAT_SHORT;
		break;

	case  VIPS_INTERPRETATION_GREY16:
	case  VIPS_INTERPRETATION_RGB16:
		format = VIPS_FORMAT_USHORT;
		break;

	case  VIPS_INTERPRETATION_MATRIX:
		if( image->BandFmt == VIPS_FORMAT_DOUBLE )
			format = VIPS_FORMAT_DOUBLE;
		else
			format = VIPS_FORMAT_FLOAT;
		break;

	default:
		format = VIPS_FORMAT_NOTSET;
		break; 
	}

	return( format );
}

/**
 * vips_image_get_coding:
 * @image: image to get from
 *
 * Returns: the image coding
 */
VipsCoding
vips_image_get_coding( const VipsImage *image )
{
	return( image->Coding );
}

/**
 * vips_image_get_interpretation:
 * @image: image to get from
 *
 * Return the #VipsInterpretation set in the image header.
 * Use vips_image_guess_interpretation() if you want a sanity-checked value.
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

/**
 * vips_image_guess_interpretation:
 * @image: image to guess for
 *
 * Return the #VipsInterpretation for an image, guessing a sane value if
 * the set value looks crazy.
 *
 * Returns: a sensible #VipsInterpretation for the image.
 */
VipsInterpretation
vips_image_guess_interpretation( const VipsImage *image )
{
	gboolean sane;

	sane = TRUE;

	/* Coding overrides interpretation.
	 */
	switch( image->Coding ) {
	case VIPS_CODING_LABQ:
		if( image->Type != VIPS_INTERPRETATION_LABQ )
			sane = FALSE;
		break;

	case VIPS_CODING_RAD:
		if( image->Type != VIPS_INTERPRETATION_RGB )
			sane = FALSE;
		break;

	default:
		break;
	}

	switch( image->Type ) {
	case VIPS_INTERPRETATION_MULTIBAND: 
		if( image->Bands == 1 )
			sane = FALSE;
		break;

	case VIPS_INTERPRETATION_B_W: 
		/* Don't test bands, we allow bands after the first to be
		 * unused extras, like alpha.
		 */
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
	case VIPS_INTERPRETATION_HSV: 
	case VIPS_INTERPRETATION_scRGB: 
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

	case  VIPS_INTERPRETATION_MATRIX:
		if( image->Bands != 1 )
			sane = FALSE;
		break;

	default:
		g_assert_not_reached();
	}

	if( sane )
		return( vips_image_get_interpretation( image ) );
	else
		return( vips_image_default_interpretation( image ) );
}

/**
 * vips_image_get_xres:
 * @image: image to get from
 *
 * Returns: the horizontal image resolution in pixels per millimeter. 
 */
double
vips_image_get_xres( const VipsImage *image )
{
	return( image->Xres );
}

/**
 * vips_image_get_yres:
 * @image: image to get from
 *
 * Returns: the vertical image resolution in pixels per millimeter. 
 */
double
vips_image_get_yres( const VipsImage *image )
{
	return( image->Yres );
}

/**
 * vips_image_get_xoffset:
 * @image: image to get from
 *
 * Returns: the horizontal position of the image origin, in pixels.
 */
int
vips_image_get_xoffset( const VipsImage *image )
{
	return( image->Xoffset );
}

/**
 * vips_image_get_yoffset:
 * @image: image to get from
 *
 * Returns: the vertical position of the image origin, in pixels.
 */
int
vips_image_get_yoffset( const VipsImage *image )
{
	return( image->Yoffset );
}

/**
 * vips_image_get_filename:
 * @image: image to get from
 *
 * Returns: the name of the file the image was loaded from. 
 */
const char *
vips_image_get_filename( const VipsImage *image )
{
	return( image->filename );
}

/**
 * vips_image_get_mode:
 * @image: image to get from
 *
 * Image modes are things like `"t"`, meaning a memory buffer, and `"p"`
 * meaning a delayed computation. 
 *
 * Returns: the image mode.
 */
const char *
vips_image_get_mode( const VipsImage *image )
{
	return( image->mode );
}

/**
 * vips_image_get_scale:
 * @image: image to get from
 *
 * Matrix images can have an optional `scale` field for use by integer 
 * convolution. 
 *
 * Returns: the scale.
 */
double
vips_image_get_scale( const VipsImage *image )
{
	double scale;

	scale = 1.0;
	if( vips_image_get_typeof( image, "scale" ) ) 
		vips_image_get_double( image, "scale", &scale );

	return( scale );
}

/**
 * vips_image_get_offset:
 * @image: image to get from
 *
 * Matrix images can have an optional `offset` field for use by integer 
 * convolution. 
 *
 * Returns: the offset.
 */
double
vips_image_get_offset( const VipsImage *image )
{
	double offset;

	offset = 0.0;
	if( vips_image_get_typeof( image, "offset" ) ) 
		vips_image_get_double( image, "offset", &offset );

	return( offset );
}

/**
 * vips_image_get_data:
 * @image: image to get data for
 *
 * Return a pointer to the image's pixel data, if possible. This can involve
 * allocating large amounts of memory and performing a long computation. Image
 * pixels are laid out in band-packed rows.
 *
 * Since this function modifies @image, it is not threadsafe. Only call it on
 * images which you are sure have not been shared with another thread. 
 *
 * See also: vips_image_wio_input(), vips_image_copy_memory().
 *
 * Returns: (transfer none): a pointer to pixel data, if possible.
 */
const void *
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
 * Normally you copy the fields from your input images with
 * vips_image_pipelinev() and then make
 * any adjustments you need, but if you are creating an image from scratch,
 * for example vips_black() or vips_jpegload(), you do need to set all the
 * fields yourself.
 *
 * See also: vips_image_pipelinev().
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
	printf( "vips__meta_cp: copying name %s, value = %s\n", 
		meta->name, str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	(void) meta_new( dst, meta->name, &meta->value );

#ifdef DEBUG
	meta_sanity( dst );
#endif /*DEBUG*/

	return( NULL );
}

/* Copy meta on to dst. 
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

/* We have to have this as a separate entry point so we can support the old
 * vips7 API.
 */
int 
vips__image_copy_fields_array( VipsImage *out, VipsImage *in[] )
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
	 *
	 * Don't destroy the meta on out. Things like foreign.c like setting
	 * image properties before calling a subclass loader, and those
	 * subclass loaders will sometimes write to an image. 
	 */
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

/** 
 * vips_image_set:
 * @image: image to set the metadata on
 * @name: the name to give the metadata
 * @value: the %GValue to copy into the image
 *
 * Set a piece of metadata on @image. Any old metadata with that name is
 * destroyed. The %GValue is copied into the image, so you need to unset the
 * value when you're done with it.
 *
 * For example, to set an integer on an image (though you would use the
 * convenience function vips_image_set_int() in practice), you would do:
 *
 * |[
 * GValue value = { 0 };
 *
 * g_value_init (&amp;value, G_TYPE_INT);
 * g_value_set_int (&amp;value, 42);
 * vips_image_set (image, name, &amp;value);
 * g_value_unset (&amp;value);
 * ]|
 *
 * See also: vips_image_get().
 */
void
vips_image_set( VipsImage *image, const char *name, GValue *value )
{
	g_assert( name );
	g_assert( value );

	meta_init( image );
	(void) meta_new( image, name, value );

#ifdef DEBUG
	meta_sanity( image );
#endif /*DEBUG*/
}

/* Unforunately gvalue seems to have no way of doing this. Just handle the vips
 * built-in types.
 */
static void
vips_set_value_from_pointer( GValue *value, void *data )
{
	GType type = G_VALUE_TYPE( value );

	/* The fundamental type ... eg. G_TYPE_ENUM for a VIPS_TYPE_KERNEL,
	 * or G_TYPE_OBJECT for VIPS_TYPE_IMAGE().
	 */
	GType fundamental = G_TYPE_FUNDAMENTAL( type );

	if( fundamental == G_TYPE_INT )
		g_value_set_int( value, *((int *) data) ); 
	else if( fundamental == G_TYPE_DOUBLE )
		g_value_set_double( value, *((double *) data) ); 
	else if( fundamental == G_TYPE_ENUM )
		g_value_set_enum( value, *((int *) data) ); 
	else if( fundamental == G_TYPE_STRING ) 
		g_value_set_string( value, *((char **) data) ); 
	else
		g_warning( "%s: unimplemented vips_set_value_from_pointer() "
			"type %s",
			G_STRLOC,
			g_type_name( type ) );
}

/**
 * vips_image_get:
 * @image: image to get the field from from
 * @name: the name to fetch
 * @value_copy: (transfer full) (out caller-allocates): the %GValue is copied into this
 *
 * Fill @value_copy with a copy of the header field. @value_copy must be zeroed 
 * but uninitialised.
 *
 * This will return -1 and add a message to the error buffer if the field
 * does not exist. Use vips_image_get_typeof() to test for the 
 * existence of a field first if you are not certain it will be there.
 *
 * For example, to read a double from an image (though of course you would use
 * vips_image_get_double() in practice):
 *
 * |[
 * GValue value = { 0 };
 * double d;
 *
 * if (vips_image_get (image, name, &amp;value))
 *   return -1;
 *
 * if (G_VALUE_TYPE (&amp;value) != G_TYPE_DOUBLE) {
 *   vips_error( "mydomain", 
 *     _("field \"%s\" is of type %s, not double"),
 *     name, 
 *     g_type_name (G_VALUE_TYPE (&amp;value)));
 *   g_value_unset (&amp;value);
 *   return -1;
 * }
 *
 * d = g_value_get_double (&amp;value);
 * g_value_unset (&amp;value);
 * ]|
 *
 * See also: vips_image_get_typeof(), vips_image_get_double().
 *
 * Returns: (skip): 0 on success, -1 otherwise.
 */
int
vips_image_get( const VipsImage *image, const char *name, GValue *value_copy )
{
	int i;
	VipsMeta *meta;

	g_assert( name );
	g_assert( value_copy );

	for( i = 0; i < VIPS_NUMBER( vips_header_fields ); i++ ) {
		HeaderField *field = &vips_header_fields[i];

		if( strcmp( field->name, name ) == 0 ) {
			GType gtype = g_type_from_name( field->type );

			g_value_init( value_copy, gtype );
			vips_set_value_from_pointer( value_copy, 
				G_STRUCT_MEMBER_P( image, field->offset ) );
			return( 0 );
		}
	}

	for( i = 0; i < VIPS_NUMBER( vips_header_fields_old ); i++ ) {
		HeaderField *field = &vips_header_fields_old[i];

		if( strcmp( field->name, name ) == 0 ) {
			GType gtype = g_type_from_name( field->type );

			g_value_init( value_copy, gtype );
			vips_set_value_from_pointer( value_copy, 
				G_STRUCT_MEMBER_P( image, field->offset ) );
			return( 0 );
		}
	}

	if( image->meta && 
		(meta = g_hash_table_lookup( image->meta, name )) ) {
		g_value_init( value_copy, G_VALUE_TYPE( &meta->value ) );
		g_value_copy( &meta->value, value_copy );

		return( 0 );
	}

	vips_error( "vips_image_get", _( "field \"%s\" not found" ), name );

	return( -1 );
}

/**
 * vips_image_get_typeof:
 * @image: image to test
 * @name: the name to search for
 *
 * Read the %GType for a header field. Returns zero if there is no
 * field of that name. 
 *
 * See also: vips_image_get().
 *
 * Returns: the %GType of the field, or zero if there is no
 * field of that name.
 */
GType 
vips_image_get_typeof( const VipsImage *image, const char *name )
{
	int i;
	VipsMeta *meta;

	g_assert( name );

	for( i = 0; i < VIPS_NUMBER( vips_header_fields ); i++ ) {
		HeaderField *field = &vips_header_fields[i];

		if( strcmp( field->name, name ) == 0 ) 
			return( g_type_from_name( field->type ) ); 
	}

	for( i = 0; i < VIPS_NUMBER( vips_header_fields_old ); i++ ) {
		HeaderField *field = &vips_header_fields_old[i];

		if( strcmp( field->name, name ) == 0 ) 
			return( g_type_from_name( field->type ) ); 
	}

	if( image->meta && 
		(meta = g_hash_table_lookup( image->meta, name )) ) 
		return( G_VALUE_TYPE( &meta->value ) );

	VIPS_DEBUG_MSG( "vips_image_get_typeof: unknown field %s\n", name );

	return( 0 );
}

/**
 * vips_image_remove:
 * @image: image to test
 * @name: the name to search for
 *
 * Find and remove an item of metadata. Return %FALSE if no metadata of that
 * name was found.
 *
 * See also: vips_image_set(), vips_image_get_typeof().
 *
 * Returns: %TRUE if an item of metadata of that name was found and removed
 */
gboolean
vips_image_remove( VipsImage *image, const char *name )
{
	if( image->meta && 
		g_hash_table_remove( image->meta, name ) )
		return( TRUE );

	return( FALSE );
}

static void *
vips_image_map_fn( VipsMeta *meta, VipsImageMapFn fn, void *a )
{
	return( fn( meta->im, meta->name, &meta->value, a ) );
}

/**
 * vips_image_map: 
 * @image: image to map over
 * @fn: (scope call): function to call for each header field
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
 * Returns: (transfer none): %NULL on success, the failing pointer otherwise.
 */
void *
vips_image_map( VipsImage *image, VipsImageMapFn fn, void *a )
{
	int i;
	GValue value = { 0 };
	void *result;

	for( i = 0; i < VIPS_NUMBER( vips_header_fields ); i++ ) {
		HeaderField *field = &vips_header_fields[i];

		(void) vips_image_get( image, field->name, &value );
		result = fn( image, field->name, &value, a );
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

static void *
count_fields( VipsImage *image, const char *field, GValue *value, void *a )
{
	int *n_fields = (int *) a;

	*n_fields += 1;

	return( NULL ); 
}

static void *
add_fields( VipsImage *image, const char *field, GValue *value, void *a )
{
	gchar ***p = (gchar ***) a;

	**p = g_strdup( field ); 
	*p += 1;

	return( NULL ); 
}

/**
 * vips_image_get_fields:
 * @image: image to get fields from
 *
 * Get a %NULL-terminated array listing all the metadata field names on @image. 
 * Free the return result with g_strfreev().
 *
 * This is handy for language bindings. From C, it's usually more convenient to
 * use vips_image_map().
 *
 * Returns: (transfer full): metadata fields in image, as a %NULL-terminated
 * array. 
 */
gchar ** 
vips_image_get_fields( VipsImage *image )
{
	int n_fields;
	gchar **fields;
	gchar **p;

	n_fields = 0;
	(void) vips_image_map( image, count_fields, &n_fields );
	fields = g_new0( gchar *, n_fields + 1 ); 
	p = fields;
	(void) vips_image_map( image, add_fields, &p );

	return( fields ); 
}

/**
 * vips_image_set_area:
 * @image: image to attach the metadata to
 * @name: metadata name
 * @free_fn: (scope async): free function for @data
 * @data: pointer to area of memory
 *
 * Attaches @data as a metadata item on @image under the name @name. When
 * VIPS no longer needs the metadata, it will be freed with @free_fn.
 *
 * See also: vips_image_get_double(), vips_image_set()
 */
void
vips_image_set_area( VipsImage *image, const char *name,
	VipsCallbackFn free_fn, void *data )
{
	GValue value = { 0 };

	vips_value_set_area( &value, free_fn, data );
	vips_image_set( image, name, &value );
	g_value_unset( &value );
}

static int
meta_get_value( const VipsImage *image,
	const char *name, GType type, GValue *value_copy )
{
	GValue value = { 0 }; 

	if( vips_image_get( image, name, &value ) )
		return( -1 );
	g_value_init( value_copy, type );
	if( !g_value_transform( &value, value_copy ) ) { 
		vips_error( "VipsImage",
			_( "field \"%s\" is of type %s, not %s" ),
			name,
			g_type_name( G_VALUE_TYPE( &value ) ),
			g_type_name( type ) );
		g_value_unset( &value );

		return( -1 );
	}
	g_value_unset( &value );

	return( 0 );
}

/**
 * vips_image_get_area:
 * @image: image to get the metadata from
 * @name: metadata name
 * @data: return metadata value
 *
 * Gets @data from @image under the name @name. A convenience
 * function over vips_image_get(). Use vips_image_get_typeof() to test for
 * the existance of a piece of metadata.
 *
 * See also: vips_image_set_area(), vips_image_get(),
 * vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_area( const VipsImage *image, const char *name, void **data )
{
	GValue value_copy = { 0 };

	if( !meta_get_value( image, name, VIPS_TYPE_AREA, &value_copy ) ) {
		*data = vips_value_get_area( &value_copy, NULL );
		g_value_unset( &value_copy );
		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_set_blob:
 * @image: image to attach the metadata to
 * @name: metadata name
 * @free_fn: (scope async): free function for @data
 * @data: pointer to area of memory
 * @length: length of memory area
 *
 * Attaches @blob as a metadata item on @image under the name @name. A 
 * convenience
 * function over vips_image_set() using a vips_blob.
 *
 * See also: vips_image_get_blob(), vips_image_set().
 */
void
vips_image_set_blob( VipsImage *image, const char *name, 
	VipsCallbackFn free_fn, void *data, size_t length )
{
	GValue value = { 0 };

	g_value_init( &value, VIPS_TYPE_BLOB );
	vips_value_set_blob( &value, free_fn, data, length );
	vips_image_set( image, name, &value );
	g_value_unset( &value );
}

/** 
 * vips_image_get_blob: 
 * @image: image to get the metadata from
 * @name: metadata name
 * @data: pointer to area of memory
 * @length: return the blob length here, optionally
 *
 * Gets @blob from @image under the name @name, optionally returns its length in
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
vips_image_get_blob( const VipsImage *image, const char *name, 
	void **data, size_t *length )
{
	GValue value_copy = { 0 };

	if( !meta_get_value( image, name, VIPS_TYPE_BLOB, &value_copy ) ) {
		*data = vips_value_get_blob( &value_copy, length );
		g_value_unset( &value_copy );
		return( 0 );
	}

	return( -1 );
}

/** 
 * vips_image_get_int:
 * @image: image to get the header field from
 * @name: field name
 * @out: return field value
 *
 * Gets @out from @im under the name @name. 
 * The value will be transformed into
 * an int, if possible. 
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_int( const VipsImage *image, const char *name, int *out )
{
	GValue value = { 0 };

	if( meta_get_value( image, name, G_TYPE_INT, &value ) ) 
		return( -1 ); 
	*out = g_value_get_int( &value );
	g_value_unset( &value );

	return( 0 );
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
 * @name: field name
 * @out: return field value
 *
 * Gets @out from @im under the name @name. 
 * The value will be transformed into
 * a double, if possible. 
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_double( const VipsImage *image, const char *name, double *out )
{
	GValue value = { 0 };

	if( meta_get_value( image, name, G_TYPE_DOUBLE, &value ) ) 
		return( -1 ); 
	*out = g_value_get_double( &value );
	g_value_unset( &value );

	return( 0 );
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
 * @name: field name
 * @out: (transfer none): return field value
 *
 * Gets @out from @im under the name @name. 
 * The field must be of type
 * VIPS_TYPE_REFSTRING.
 *
 * Do not free @out.
 *
 * Use vips_image_get_as_string() to fetch any field as a string.
 *
 * See also: vips_image_get(), vips_image_get_typeof()
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_string( const VipsImage *image, const char *name, 
	const char **out )
{
	GValue value = { 0 };
	VipsArea *area;

	if( vips_image_get( image, name, &value ) )
		return( -1 );
	if( G_VALUE_TYPE( &value ) != VIPS_TYPE_REF_STRING ) {
		vips_error( "VipsImage",
			_( "field \"%s\" is of type %s, not VipsRefString" ),
			name,
			g_type_name( G_VALUE_TYPE( &value ) ) );
		g_value_unset( &value );
		return( -1 );
	}

	area = g_value_get_boxed( &value );
	*out = area->data;
	g_value_unset( &value );

	return( 0 );
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
 * @out: (transfer full): return field value as string
 *
 * Gets @out from @im under the name @field. 
 * This function will read any field, returning it as a printable string.
 * You need to free the string with g_free() when you are done with it.
 *
 * This will base64-encode BLOBs, for example. Use vips_buf_appendgv() to 
 * make a string that's for humans. 
 *
 * See also: vips_image_get(), vips_image_get_typeof(), vips_buf_appendgv().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_image_get_as_string( const VipsImage *image, 
	const char *field, char **out )
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
 * vips_image_print_field:
 * @image: image to get the header field from
 * @field: field name
 *
 * Prints a field to stdout as ASCII. Handy for debugging. 
 */
void
vips_image_print_field( const VipsImage *image, const char *field )
{
	char *str;

	if( vips_image_get_as_string( image, field, &str ) ) {
		printf( "vips_image_print_field: unable to read field\n" );
		return;
	}

	printf( ".%s: %s\n", field, str );

	g_free( str ); 
}

/**
 * vips_image_history_printf:
 * @image: add history line to this image
 * @format: printf() format string
 * @...: arguments to format string
 *
 * Add a line to the image history. The @format and arguments are expanded, the
 * date and time is appended prefixed with a hash character, and the whole
 * string is appended to the image history and terminated with a newline.
 *
 * For example:
 *
 * |[
 * vips_image_history_printf (image, "vips invert %s %s", 
 *   in->filename, out->filename);
 * ]|
 *
 * Might add the string
 *
 * |[
 * "vips invert /home/john/fred.v /home/john/jim.v # Fri Apr 3 23:30:35 2009\n"
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
	char str[VIPS_PATH_MAX];
	VipsBuf buf = VIPS_BUF_STATIC( str );
	time_t timebuf;

	va_start( args, fmt );
	(void) vips_buf_vappendf( &buf, fmt, args );
	va_end( args );
	vips_buf_appends( &buf, " # " );

	/* Add the date. ctime always attaches a '\n', gah.
	 */
	time( &timebuf );
	vips_buf_appends( &buf, ctime( &timebuf ) ); 
	vips_buf_removec( &buf, '\n' ); 

#ifdef DEBUG
	printf( "vips_image_history_printf: "
		"adding:\n\t%s\nto history on image %p\n", 
		vips_buf_all( &buf ), image );
#endif /*DEBUG*/

	image->history_list = g_slist_append( image->history_list, 
		vips__gvalue_ref_string_new( vips_buf_all( &buf ) ) );

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
 * Returns: (transfer none): The history of @image as a C string. Do not free!
 */
const char *
vips_image_get_history( VipsImage *image )
{
	if( !image->Hist )
		image->Hist = vips__gslist_gvalue_get( image->history_list );

	return( image->Hist ? image->Hist : "" );
}
