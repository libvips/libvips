/* parse EXIF metadata block out into a set of fields, and reassemble EXIF
 * block from original block, plus modified fields
 *
 * 7/11/16
 *      - from jpeg2vips
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef HAVE_EXIF

#ifdef UNTAGGED_EXIF
#include <exif-data.h>
#include <exif-loader.h>
#include <exif-ifd.h>
#include <exif-utils.h>
#else /*!UNTAGGED_EXIF*/
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-utils.h>
#endif /*UNTAGGED_EXIF*/

#include "pforeign.h"

#ifdef DEBUG_VERBOSE
/* Print exif for debugging ... hacked from exif-0.6.9/actions.c
 */
static void
show_tags( ExifData *data )
{
	int i;
	unsigned int tag;
	const char *name;

	printf( "show EXIF tags:\n" );

        for( i = 0; i < EXIF_IFD_COUNT; i++ )
                printf( "%-7.7s", exif_ifd_get_name( i ) );
	printf( "\n" );

        for( tag = 0; tag < 0xffff; tag++ ) {
                name = exif_tag_get_title( tag );
                if( !name )      
                        continue;   
                printf( "  0x%04x %-29.29s", tag, name );
                for( i = 0; i < EXIF_IFD_COUNT; i++ )
                        if( exif_content_get_entry( data->ifd[i], tag ) )
                                printf( "   *   " );
                        else
                                printf( "   -   " );
		printf( "\n" );
        }
}

static void
show_entry( ExifEntry *entry, void *client )
{
	char exif_text[256];

	printf( "%s", exif_tag_get_title( entry->tag ) );
        printf( "|" );
	printf( "%s", exif_entry_get_value( entry, exif_text, 256 ) );
        printf( "|" );
	printf( "%s", exif_format_get_name( entry->format ) );
        printf( "|" );
	printf( "%d bytes", entry->size );
        printf( "\n" );
}

static void
show_ifd( ExifContent *content, void *client )
{
	int *ifd = (int *) client;

        printf( "- ifd %d\n", *ifd );
        exif_content_foreach_entry( content, show_entry, client );

	*ifd += 1;
}

static void
show_values( ExifData *data )
{
        ExifByteOrder order;
	int ifd;

        order = exif_data_get_byte_order( data );
        printf( "EXIF tags in '%s' byte order\n", 
		exif_byte_order_get_name( order ) );

	printf( "Title|Value|Format|Size\n" ); 

	ifd = 0;
        exif_data_foreach_content( data, show_ifd, &ifd );

        if( data->size ) 
                printf( "contains thumbnail of %d bytes\n", data->size );
}
#endif /*DEBUG_VERBOSE*/

/* Like exif_data_new_from_data(), but don't default missing fields. 
 * 
 * If we do exif_data_new_from_data(), then missing fields are set to 
 * their default value and we won't know about it. 
 */
static ExifData *
vips_exif_load_data_without_fix( void *data, int length )
{
	ExifData *ed;

	if( !(ed = exif_data_new()) ) {
		vips_error( "exif", "%s", _( "unable to init exif" ) ); 
		return( NULL );
	}

	exif_data_unset_option( ed, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION );
	exif_data_load_data( ed, data, length );

	return( ed );
}

static int
vips_exif_get_int( ExifData *ed, 
	ExifEntry *entry, unsigned long component, int *out )
{
	ExifByteOrder bo = exif_data_get_byte_order( ed );
	size_t sizeof_component = entry->size / entry->components;
	size_t offset = component * sizeof_component;

	if( entry->format == EXIF_FORMAT_SHORT ) 
		*out = exif_get_short( entry->data + offset, bo );
	else if( entry->format == EXIF_FORMAT_SSHORT ) 
		*out = exif_get_sshort( entry->data + offset, bo );
	else if( entry->format == EXIF_FORMAT_LONG ) 
		/* This won't work for huge values, but who cares.
		 */
		*out = (int) exif_get_long( entry->data + offset, bo );
	else if( entry->format == EXIF_FORMAT_SLONG ) 
		*out = exif_get_slong( entry->data + offset, bo );
	else
		return( -1 );

	return( 0 );
}

static int
vips_exif_get_rational( ExifData *ed, 
	ExifEntry *entry, unsigned long component, ExifRational *out )
{
	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifByteOrder bo = exif_data_get_byte_order( ed );
		size_t sizeof_component = entry->size / entry->components;
		size_t offset = component * sizeof_component;

		*out = exif_get_rational( entry->data + offset, bo );
	}
	else
		return( -1 );

	return( 0 );
}

static int
vips_exif_get_srational( ExifData *ed, 
	ExifEntry *entry, unsigned long component, ExifSRational *out )
{
	if( entry->format == EXIF_FORMAT_SRATIONAL ) {
		ExifByteOrder bo = exif_data_get_byte_order( ed );
		size_t sizeof_component = entry->size / entry->components;
		size_t offset = component * sizeof_component;

		*out = exif_get_srational( entry->data + offset, bo );
	}
	else
		return( -1 );

	return( 0 );
}

static int
vips_exif_get_double( ExifData *ed, 
	ExifEntry *entry, unsigned long component, double *out )
{
	ExifRational rv;
	ExifSRational srv;

	if( !vips_exif_get_rational( ed, entry, component, &rv ) ) 
		*out = (double) rv.numerator / rv.denominator;
	else if( !vips_exif_get_srational( ed, entry, component, &srv ) ) 
		*out = (double) srv.numerator / srv.denominator;
	else
		return( -1 );

	return( 0 );
}

/* Save an exif value to a string in a way that we can restore. We only bother
 * for the simple formats (that a client might try to change) though.
 *
 * Keep in sync with vips_exif_from_s() below.
 */
static void
vips_exif_to_s( ExifData *ed, ExifEntry *entry, VipsBuf *buf )
{
	unsigned long i;
	int iv;
	ExifRational rv;
	ExifSRational srv;
	char txt[256];

	if( entry->format == EXIF_FORMAT_ASCII )  {
		/* libexif does not null-terminate strings. Copy out and add
		 * the \0 ourselves.
		 */
		int len = VIPS_MIN( 254, entry->size ); 

		memcpy( txt, entry->data, len );
		txt[len] = '\0';
		vips_buf_appendf( buf, "%s ", txt );
	}
	else if( entry->components < 10 &&
		!vips_exif_get_int( ed, entry, 0, &iv ) ) {
		for( i = 0; i < entry->components; i++ ) {
			vips_exif_get_int( ed, entry, i, &iv );
			vips_buf_appendf( buf, "%d ", iv );
		}
	}
	else if( entry->components < 10 &&
		!vips_exif_get_rational( ed, entry, 0, &rv ) ) {
		for( i = 0; i < entry->components; i++ ) {
			vips_exif_get_rational( ed, entry, i, &rv );
			vips_buf_appendf( buf, "%u/%u ", 
				rv.numerator, rv.denominator );
		}
	}
	else if( entry->components < 10 &&
		!vips_exif_get_srational( ed, entry, 0, &srv ) ) {
		for( i = 0; i < entry->components; i++ ) {
			vips_exif_get_srational( ed, entry, i, &srv );
			vips_buf_appendf( buf, "%d/%d ", 
				srv.numerator, srv.denominator );
		}
	}
	else 
		vips_buf_appendf( buf, "%s ", 
			exif_entry_get_value( entry, txt, 256 ) );

	vips_buf_appendf( buf, "(%s, %s, %lu components, %d bytes)", 
		exif_entry_get_value( entry, txt, 256 ),
		exif_format_get_name( entry->format ),
		entry->components,
		entry->size );
}

typedef struct _VipsExifParams {
	VipsImage *image;
	ExifData *ed;
} VipsExifParams;

static void
vips_exif_attach_entry( ExifEntry *entry, VipsExifParams *params )
{
	const char *tag_name;
	char vips_name_txt[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( vips_name_txt );
	char value_txt[256];
	VipsBuf value = VIPS_BUF_STATIC( value_txt );

	if( !(tag_name = exif_tag_get_name( entry->tag )) )
		return;

	vips_buf_appendf( &vips_name, "exif-ifd%d-%s", 
		exif_entry_get_ifd( entry ), tag_name );
	vips_exif_to_s( params->ed, entry, &value ); 

	/* Can't do anything sensible with the error return.
	 */
	(void) vips_image_set_string( params->image, 
		vips_buf_all( &vips_name ), vips_buf_all( &value ) );
}

static void
vips_exif_get_content( ExifContent *content, VipsExifParams *params )
{
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) vips_exif_attach_entry, params );
}

static int
vips_exif_entry_get_double( ExifData *ed, int ifd, ExifTag tag, double *out )
{
	ExifEntry *entry;

	if( !(entry = exif_content_get_entry( ed->ifd[ifd], tag )) ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_double( ed, entry, 0, out ) );
}

static int
vips_exif_entry_get_int( ExifData *ed, int ifd, ExifTag tag, int *out )
{
	ExifEntry *entry;

	if( !(entry = exif_content_get_entry( ed->ifd[ifd], tag )) ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_int( ed, entry, 0, out ) );
}

/* Set the image resolution from the EXIF tags.
 */
static int
vips_image_resolution_from_exif( VipsImage *image, ExifData *ed )
{
	double xres, yres;
	int unit;

	/* The main image xres/yres are in ifd0. ifd1 has xres/yres of the
	 * image thumbnail, if any.
	 */
	if( vips_exif_entry_get_double( ed, 0, EXIF_TAG_X_RESOLUTION, &xres ) ||
		vips_exif_entry_get_double( ed, 
			0, EXIF_TAG_Y_RESOLUTION, &yres ) ||
		vips_exif_entry_get_int( ed, 
			0, EXIF_TAG_RESOLUTION_UNIT, &unit ) ) {
		vips_warn( "exif", "%s", _( "error reading resolution" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_image_resolution_from_exif: seen exif tags "
		"xres = %g, yres = %g, unit = %d\n", xres, yres, unit );
#endif /*DEBUG*/

	switch( unit ) {
	case 1:
		/* No unit ... just pass the fields straight to vips.
		 */
		vips_image_set_string( image, 
			VIPS_META_RESOLUTION_UNIT, "none" );
		break;

	case 2:
		/* In inches.
		 */
		xres /= 25.4;
		yres /= 25.4;
		vips_image_set_string( image, 
			VIPS_META_RESOLUTION_UNIT, "in" );
		break;

	case 3:
		/* In cm.
		 */
		xres /= 10.0;
		yres /= 10.0;
		vips_image_set_string( image, 
			VIPS_META_RESOLUTION_UNIT, "cm" );
		break;

	default:
		vips_warn( "exif", 
			"%s", _( "unknown EXIF resolution unit" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_image_resolution_from_exif: "
		"seen exif resolution %g, %g p/mm\n", xres, yres );
#endif /*DEBUG*/

	image->Xres = xres;
	image->Yres = yres;

	return( 0 );
}

static int
vips_exif_get_thumbnail( VipsImage *im, ExifData *ed )
{
	if( ed->size > 0 ) {
		char *thumb_copy;

		thumb_copy = g_malloc( ed->size );      
		memcpy( thumb_copy, ed->data, ed->size );

		vips_image_set_blob( im, "jpeg-thumbnail-data", 
			(VipsCallbackFn) g_free, thumb_copy, ed->size );
	}

	return( 0 );
}

static void *
vips_exif_get_orientation( VipsImage *image, 
	const char *field, GValue *value, void *data )
{
	const char *orientation_str;

	if( vips_isprefix( "exif-", field ) &&
		vips_ispostfix( field, "-Orientation" ) &&
		!vips_image_get_string( image, field, &orientation_str ) ) {
		int orientation;

		orientation = atoi( orientation_str );
		orientation = VIPS_CLIP( 1, orientation, 8 );
		vips_image_set_int( image, VIPS_META_ORIENTATION, orientation );

		return( image ); 
	}

	return( NULL );
}

/* Need to fwd ref this.
 */
static int
vips_exif_resolution_from_image( ExifData *ed, VipsImage *image );

/* Scan the exif block on the image, if any, and make a set of vips metadata 
 * tags for what we find.
 */
int
vips__exif_parse( VipsImage *image )
{
	void *data;
	size_t length;
	ExifData *ed;
	VipsExifParams params;

	if( !vips_image_get_typeof( image, VIPS_META_EXIF_NAME ) )
		return( 0 );
	if( vips_image_get_blob( image, VIPS_META_EXIF_NAME, &data, &length ) )
		return( -1 ); 
	if( !(ed = vips_exif_load_data_without_fix( data, length )) )
		return( -1 );

#ifdef DEBUG_VERBOSE
	show_tags( ed );
	show_values( ed );
#endif /*DEBUG_VERBOSE*/

	/* Look for resolution fields and use them to set the VIPS xres/yres 
	 * fields.
	 *
	 * If the fields are missing, set them from the image, which will have
	 * previously had them set from something like JFIF. 
	 */
	if( vips_image_resolution_from_exif( image, ed ) &&
		vips_exif_resolution_from_image( ed, image ) ) {
		exif_data_free( ed );
		return( -1 ); 
	}

	/* Make sure all required fields are there before we attach to vips
	 * metadata.
	 */
	exif_data_fix( ed );

	/* Attach informational fields for what we find.
	 */
	params.image = image;
	params.ed = ed;
	exif_data_foreach_content( ed, 
		(ExifDataForeachContentFunc) vips_exif_get_content, &params );

	vips_exif_get_thumbnail( image, ed );
	exif_data_free( ed );

	/* Orientation handling. We look for the first Orientation EXIF tag
	 * (there can be many of them) and use that to set our own
	 * VIPS_META_ORIENTATION. 
	 *
	 * ifd0 is usually the image, ifd1 the thumbnail. 
	 */
	(void) vips_image_map( image, vips_exif_get_orientation, NULL );

	return( 0 );
}

static void
vips_exif_set_int( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data )
{
	int value = *((int *) data);

	ExifByteOrder bo;
	size_t sizeof_component;
	size_t offset = component;

	if( entry->components <= component ) {
		VIPS_DEBUG_MSG( "vips_exif_set_int: too few components\n" );
		return;
	}

	/* Wait until after the component check to make sure we cant get /0.
	 */
	bo = exif_data_get_byte_order( ed );
	sizeof_component = entry->size / entry->components;
	offset = component * sizeof_component;

	VIPS_DEBUG_MSG( "vips_exif_set_int: %s = %d\n",
		exif_tag_get_name( entry->tag ), value );

	if( entry->format == EXIF_FORMAT_SHORT ) 
		exif_set_short( entry->data + offset, bo, value );
	else if( entry->format == EXIF_FORMAT_SSHORT ) 
		exif_set_sshort( entry->data + offset, bo, value );
	else if( entry->format == EXIF_FORMAT_LONG ) 
		exif_set_long( entry->data + offset, bo, value );
	else if( entry->format == EXIF_FORMAT_SLONG ) 
		exif_set_slong( entry->data + offset, bo, value );
}

static void
vips_exif_double_to_rational( double value, ExifRational *rv )
{
	/* We will usually set factors of 10, so use 1000 as the denominator
	 * and it'll probably be OK.
	 */
	rv->numerator = value * 1000;
	rv->denominator = 1000;
}

static void
vips_exif_double_to_srational( double value, ExifSRational *srv )
{
	/* We will usually set factors of 10, so use 1000 as the denominator
	 * and it'll probably be OK.
	 */
	srv->numerator = value * 1000;
	srv->denominator = 1000;
}

/* Parse a char* into an ExifRational. We allow floats as well.
 */
static void
vips_exif_parse_rational( const char *str, ExifRational *rv )
{
	if( sscanf( str, " %u / %u ", &rv->numerator, &rv->denominator ) == 2 )
		return;
	vips_exif_double_to_rational( g_ascii_strtod( str, NULL ), rv );
}

/* Parse a char* into an ExifSRational. We allow floats as well.
 */
static void
vips_exif_parse_srational( const char *str, ExifSRational *srv )
{
	if( sscanf( str, " %d / %d ", 
		&srv->numerator, &srv->denominator ) == 2 )
		return;
	vips_exif_double_to_srational( g_ascii_strtod( str, NULL ), srv );
}

/* Does both signed and unsigned rationals from a char*.
 */
static void
vips_exif_set_rational( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data )
{
	char *value = (char *) data;

	ExifByteOrder bo;
	size_t sizeof_component;
	size_t offset;

	if( entry->components <= component ) {
		VIPS_DEBUG_MSG( "vips_exif_set_rational: "
			"too few components\n" );
		return;
	}

	/* Wait until after the component check to make sure we cant get /0.
	 */
	bo = exif_data_get_byte_order( ed );
	sizeof_component = entry->size / entry->components;
	offset = component * sizeof_component;

	VIPS_DEBUG_MSG( "vips_exif_set_rational: %s = \"%s\"\n",
		exif_tag_get_name( entry->tag ), value );

	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifRational rv;

		vips_exif_parse_rational( value, &rv ); 

		VIPS_DEBUG_MSG( "vips_exif_set_rational: %u / %u\n", 
			rv.numerator, 
			rv.denominator ); 

		exif_set_rational( entry->data + offset, bo, rv );
	}
	else if( entry->format == EXIF_FORMAT_SRATIONAL ) {
		ExifSRational srv;

		vips_exif_parse_srational( value, &srv ); 

		VIPS_DEBUG_MSG( "vips_exif_set_rational: %d / %d\n", 
			srv.numerator, srv.denominator ); 

		exif_set_srational( entry->data + offset, bo, srv );
	}
}

/* Does both signed and unsigned rationals from a double*.
 *
 * Don't change the exit entry if the value currently there is a good
 * approximation of the double we are trying to set.
 */
static void
vips_exif_set_double( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data )
{
	double value = *((double *) data);

	ExifByteOrder bo;
	size_t sizeof_component;
	size_t offset;
	double old_value;

	if( entry->components <= component ) {
		VIPS_DEBUG_MSG( "vips_exif_set_double: "
			"too few components\n" );
		return;
	}

	/* Wait until after the component check to make sure we cant get /0.
	 */
	bo = exif_data_get_byte_order( ed );
	sizeof_component = entry->size / entry->components;
	offset = component * sizeof_component;

	VIPS_DEBUG_MSG( "vips_exif_set_double: %s = %g\n",
		exif_tag_get_name( entry->tag ), value );

	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifRational rv;

		rv = exif_get_rational( entry->data + offset, bo );
		old_value = (double) rv.numerator / rv.denominator;
		if( VIPS_FABS( old_value - value ) > 0.0001 ) {
			vips_exif_double_to_rational( value, &rv ); 

			VIPS_DEBUG_MSG( "vips_exif_set_double: %u / %u\n", 
				rv.numerator, 
				rv.denominator ); 

			exif_set_rational( entry->data + offset, bo, rv );
		}
	}
	else if( entry->format == EXIF_FORMAT_SRATIONAL ) {
		ExifSRational srv;

		srv = exif_get_srational( entry->data + offset, bo );
		old_value = (double) srv.numerator / srv.denominator;
		if( VIPS_FABS( old_value - value ) > 0.0001 ) {
			vips_exif_double_to_srational( value, &srv ); 

			VIPS_DEBUG_MSG( "vips_exif_set_double: %d / %d\n", 
				srv.numerator, srv.denominator ); 

			exif_set_srational( entry->data + offset, bo, srv );
		}
	}
}

typedef void (*write_fn)( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data );

/* Write a tag. Update what's there, or make a new one.
 */
static void
vips_exif_set_tag( ExifData *ed, int ifd, ExifTag tag, write_fn fn, void *data )
{
	ExifEntry *entry;

	if( (entry = exif_content_get_entry( ed->ifd[ifd], tag )) ) {
		fn( ed, entry, 0, data );
	}
	else {
		entry = exif_entry_new();

		/* tag must be set before calling exif_content_add_entry.
		 */
		entry->tag = tag; 

		exif_content_add_entry( ed->ifd[ifd], entry );
		exif_entry_initialize( entry, tag );
		exif_entry_unref( entry );

		fn( ed, entry, 0, data );
	}
}

/* Set the EXIF resolution from the vips xres/yres tags.
 */
static int
vips_exif_resolution_from_image( ExifData *ed, VipsImage *image )
{
	double xres, yres;
	const char *p;
	int unit;

	VIPS_DEBUG_MSG( "vips_exif_resolution_from_image: vips res of %g, %g\n",
		image->Xres, image->Yres );

	/* Default to inches, more progs support it.
	 */
	unit = 2;
	if( vips_image_get_typeof( image, VIPS_META_RESOLUTION_UNIT ) &&
		!vips_image_get_string( image, 
			VIPS_META_RESOLUTION_UNIT, &p ) ) {
		if( vips_isprefix( "cm", p ) ) 
			unit = 3;
		else if( vips_isprefix( "none", p ) ) 
			unit = 1;
	}

	switch( unit ) {
	case 1:
		xres = image->Xres;
		yres = image->Yres;
		break;

	case 2:
		xres = image->Xres * 25.4;
		yres = image->Yres * 25.4;
		break;

	case 3:
		xres = image->Xres * 10.0;
		yres = image->Yres * 10.0;
		break;

	default:
		vips_warn( "exif", 
			"%s", _( "unknown EXIF resolution unit" ) );
		return( 0 );
	}

	/* Main image xres/yres/unit are in ifd0. ifd1 has the thumbnail
	 * xres/yres/unit.
	 */
	vips_exif_set_tag( ed, 0, EXIF_TAG_X_RESOLUTION, 
		vips_exif_set_double, (void *) &xres );
	vips_exif_set_tag( ed, 0, EXIF_TAG_Y_RESOLUTION, 
		vips_exif_set_double, (void *) &yres );
	vips_exif_set_tag( ed, 0, EXIF_TAG_RESOLUTION_UNIT, 
		vips_exif_set_int, (void *) &unit );

	return( 0 );
}

/* Exif also tracks image dimensions. 
 */
static int
vips_exif_set_dimensions( ExifData *ed, VipsImage *im )
{
	VIPS_DEBUG_MSG( "vips_exif_set_dimensions: vips size of %d, %d\n",
		im->Xsize, im->Ysize );

	vips_exif_set_tag( ed, 2, EXIF_TAG_PIXEL_X_DIMENSION, 
		vips_exif_set_int, (void *) &im->Xsize );
	vips_exif_set_tag( ed, 2, EXIF_TAG_PIXEL_Y_DIMENSION, 
		vips_exif_set_int, (void *) &im->Ysize );

	return( 0 );
}

/* And orientation. 
 */
static int
vips_exif_set_orientation( ExifData *ed, VipsImage *im )
{
	int orientation;

	/* We set the tag, even if it's been deleted, since it's a required
	 * field.
	 */
	if( !vips_image_get_typeof( im, VIPS_META_ORIENTATION ) ||
		vips_image_get_int( im, VIPS_META_ORIENTATION, &orientation ) ) 
		orientation = 1;

	VIPS_DEBUG_MSG( "set_exif_orientation: %d\n", orientation );

	vips_exif_set_tag( ed, 0, EXIF_TAG_ORIENTATION, 
		vips_exif_set_int, (void *) &orientation );

	return( 0 );
}

/* See also vips_exif_to_s() ... keep in sync.
 */
static void
vips_exif_from_s( ExifData *ed, ExifEntry *entry, const char *value )
{
	unsigned long i;
	const char *p;

	if( entry->format != EXIF_FORMAT_SHORT &&
		entry->format != EXIF_FORMAT_SSHORT &&
		entry->format != EXIF_FORMAT_LONG &&
		entry->format != EXIF_FORMAT_SLONG &&
		entry->format != EXIF_FORMAT_RATIONAL &&
		entry->format != EXIF_FORMAT_SRATIONAL )
		return;
	if( entry->components >= 10 )
		return;

	/* Skip any leading spaces.
	 */
	p = value;
	while( *p == ' ' )
		p += 1;

	for( i = 0; i < entry->components; i++ ) {
		if( entry->format == EXIF_FORMAT_SHORT || 
			entry->format == EXIF_FORMAT_SSHORT || 
			entry->format == EXIF_FORMAT_LONG || 
			entry->format == EXIF_FORMAT_SLONG ) {
			int value = atof( p );

			vips_exif_set_int( ed, entry, i, &value );
		}
		else if( entry->format == EXIF_FORMAT_RATIONAL || 
			entry->format == EXIF_FORMAT_SRATIONAL ) 
			vips_exif_set_rational( ed, entry, i, (void *) p );

		/* Skip to the next set of spaces, then to the beginning of
		 * the next item.
		 */
		while( *p && *p != ' ' )
			p += 1;
		while( *p == ' ' )
			p += 1;
		if( !*p )
			break;
	}
}

static void 
vips_exif_set_entry( ExifData *ed, ExifEntry *entry, 
	unsigned long component, void *data )
{
	const char *string = (const char *) data; 

	vips_exif_from_s( ed, entry, string ); 
}

static void *
vips_exif_image_field( VipsImage *image, 
	const char *field, GValue *value, void *data )
{
	ExifData *ed = (ExifData *) data;

	const char *string;
	int ifd;
	const char *p;
	ExifTag tag;

	if( !vips_isprefix( "exif-ifd", field ) ) 
		return( NULL );

	/* value must be a string.
	 */
	if( vips_image_get_string( image, field, &string ) ) {
		vips_warn( "exif", _( "bad exif meta \"%s\"" ), field );
		return( NULL ); 
	}

	p = field + strlen( "exif-ifd" );
	ifd = atoi( p ); 

	for( ; isdigit( *p ); p++ )
		;
	if( *p != '-' ) {
		vips_warn( "exif", _( "bad exif meta \"%s\"" ), field );
		return( NULL ); 
	}

	if( !(tag = exif_tag_from_name( p + 1 )) ) {
		vips_warn( "exif", _( "bad exif meta \"%s\"" ), field );
		return( NULL ); 
	}

	vips_exif_set_tag( ed, ifd, tag, vips_exif_set_entry, (void *) string );

	return( NULL ); 
}

typedef struct _VipsExifRemove {
	VipsImage *image;
	ExifData *ed;
	ExifContent *content;
	GSList *to_remove;
} VipsExifRemove;

static void
vips_exif_exif_entry( ExifEntry *entry, VipsExifRemove *ve )
{
	const char *tag_name;
	char vips_name_txt[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( vips_name_txt );

	if( !(tag_name = exif_tag_get_name( entry->tag )) )
		return;

	vips_buf_appendf( &vips_name, "exif-ifd%d-%s", 
		exif_entry_get_ifd( entry ), tag_name );

	/* Does this field exist on the image? If not, schedule it for
	 * removal.
	 */
	if( !vips_image_get_typeof( ve->image, vips_buf_all( &vips_name ) ) ) 
		ve->to_remove = g_slist_prepend( ve->to_remove, entry );

	/* Orientation is really set from the vips
	 * VIPS_META_ORIENTATION tag. If that's been deleted, we must delete
	 * any matching EXIF tags too.
	 */
	if( strcmp( tag_name, "Orientation" ) == 0 &&
		vips_image_get_typeof( ve->image, VIPS_META_ORIENTATION ) )
		ve->to_remove = g_slist_prepend( ve->to_remove, entry );
}

static void *
vips_exif_exif_remove( ExifEntry *entry, VipsExifRemove *ve )
{
#ifdef DEBUG
{
	const char *tag_name;
	char vips_name_txt[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( vips_name_txt );

	tag_name = exif_tag_get_name( entry->tag );
	vips_buf_appendf( &vips_name, "exif-ifd%d-%s", 
		exif_entry_get_ifd( entry ), tag_name );

	printf( "vips_exif_exif_remove: %s\n", vips_buf_all( &vips_name ) );
}
#endif /*DEBUG*/

	exif_content_remove_entry( ve->content, entry );

	return( NULL );
}

static void
vips_exif_exif_content( ExifContent *content, VipsExifRemove *ve )
{
	ve->content = content;
	ve->to_remove = NULL;
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) vips_exif_exif_entry, ve );
	vips_slist_map2( ve->to_remove,
		(VipsSListMap2Fn) vips_exif_exif_remove, ve, NULL );
	VIPS_FREEF( g_slist_free, ve->to_remove );
}

static void
vips_exif_update( ExifData *ed, VipsImage *image )
{
	VipsExifRemove ve;

	VIPS_DEBUG_MSG( "vips_exif_update: \n" );

	/* Walk the image and update any stuff that's been changed in image
	 * metadata.
	 */
	vips_image_map( image, vips_exif_image_field, ed );

	/* Walk the exif and look for any fields which are NOT in image
	 * metadata. They must have been removed ... remove them from exif as
	 * well.
	 */
	ve.image = image;
	ve.ed = ed;
	exif_data_foreach_content( ed, 
		(ExifDataForeachContentFunc) vips_exif_exif_content, &ve );
}

/* Examine the metadata tags on the image and update the EXIF block.
 */
int
vips__exif_update( VipsImage *image )
{
	unsigned char *data;
	size_t length;
	unsigned int idl;
	ExifData *ed;

	/* Either parse from the embedded EXIF, or if there's none, make
	 * some fresh EXIF we can write the resolution to.
	 */
	if( vips_image_get_typeof( image, VIPS_META_EXIF_NAME ) ) {
		if( vips_image_get_blob( image, VIPS_META_EXIF_NAME, 
			(void *) &data, &length ) )
			return( -1 );

		if( !(ed = exif_data_new_from_data( data, length )) )
			return( -1 );
	}
	else  {
		ed = exif_data_new();

		exif_data_set_option( ed, 
			EXIF_DATA_OPTION_FOLLOW_SPECIFICATION );
		exif_data_set_data_type( ed, EXIF_DATA_TYPE_COMPRESSED );
		exif_data_set_byte_order( ed, EXIF_BYTE_ORDER_INTEL );
	
		/* Create the mandatory EXIF fields with default data.
		 */
		exif_data_fix( ed );
	}

	/* Update EXIF tags from the image metadata.
	 */
	vips_exif_update( ed, image );

	/* Update EXIF resolution from the vips image header.
	 */
	if( vips_exif_resolution_from_image( ed, image ) ) {
		exif_data_free( ed );
		return( -1 );
	}

	/* Update EXIF image dimensions from the vips image header.
	 */
	if( vips_exif_set_dimensions( ed, image ) ) {
		exif_data_free( ed );
		return( -1 );
	}

	/* Update EXIF orientation from the vips image header.
	 */
	if( vips_exif_set_orientation( ed, image ) ) {
		exif_data_free( ed );
		return( -1 );
	}

	/* Reserialise and write. exif_data_save_data() returns an int for some
	 * reason.
	 */
	exif_data_save_data( ed, &data, &idl );
	if( !idl ) {
		vips_error( "exif", "%s", _( "error saving EXIF" ) );
		exif_data_free( ed );
		return( -1 );
	}
	length = idl;

#ifdef DEBUG
	printf( "vips__exif_update: generated %zd bytes of EXIF\n", length  );
#endif /*DEBUG*/

	vips_image_set_blob( image, VIPS_META_EXIF_NAME, 
		(VipsCallbackFn) vips_free, data, length );

	return( 0 );
}

#else /*!HAVE_EXIF*/

int
vips__exif_parse( VipsImage *image )
{
	return( 0 );
}

int
vips__exif_update( VipsImage *image )
{
	return( 0 );
}

#endif /*!HAVE_EXIF*/
