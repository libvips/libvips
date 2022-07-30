/* parse EXIF metadata block out into a set of fields, and reassemble EXIF
 * block from original block, plus modified fields
 *
 * 7/11/16
 *      - from jpeg2vips
 * 14/10/17
 * 	- only read orientation from ifd0
 * 1/2/18
 * 	- remove exif thumbnail if "jpeg-thumbnail-data" has been removed
 * 3/7/18
 * 	- add support for writing string-valued fields
 * 9/7/18 [@Nan619]
 * 	- get tag name from tag plus ifd 
 * 13/11/21
 * 	- better handling of strings with embedded metacharacters
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
#include <glib/gi18n-lib.h>

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
vips_exif_load_data_without_fix( const void *data, size_t length )
{
	ExifData *ed;

	/* exif_data_load_data() only allows uint for length. Limit it to less
	 * than that: 2**20 should be enough for anyone.
	 */
	if( length > 1 << 20 ) {
		vips_error( "exif", "%s", _( "exif too large" ) ); 
		return( NULL );
	}

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
	double value;

	if( !vips_exif_get_rational( ed, entry, component, &rv ) ) {
		if( rv.denominator == 0 )
			value = 0;
		else
			value = (double) rv.numerator / rv.denominator;
	}
	else if( !vips_exif_get_srational( ed, entry, component, &srv ) ) {
		if( srv.denominator == 0 )
			value = 0;
		else
			value = (double) srv.numerator / srv.denominator;
	}
	else
		return( -1 );

	*out = value;

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

/* tags do not uniquely set tag names: the same tag can have different
 * names in different ifds.
 *
 * As long as this entry has been linked to an ifd, get the tag name.
 */
static const char *
vips_exif_entry_get_name( ExifEntry *entry )
{
	if( !entry->parent )
		return( NULL );

	return( exif_tag_get_name_in_ifd( entry->tag, 
		exif_entry_get_ifd( entry ) ) );
}

static void
vips_exif_attach_entry( ExifEntry *entry, VipsExifParams *params )
{
	const char *tag_name;
	char vips_name_txt[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( vips_name_txt );
	char value_txt[256];
	VipsBuf value = VIPS_BUF_STATIC( value_txt );

	if( !(tag_name = vips_exif_entry_get_name( entry )) )
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
	 *
	 * Don't warn about missing res fields, it's very common, especially for
	 * things like webp.
	 */
	if( vips_exif_entry_get_double( ed, 0, EXIF_TAG_X_RESOLUTION, &xres ) ||
		vips_exif_entry_get_double( ed, 
			0, EXIF_TAG_Y_RESOLUTION, &yres ) )
		return( -1 );

	/* resuint is optional and defaults to inch.
	 */
	unit = 2;
	(void) vips_exif_entry_get_int( ed, 
		0, EXIF_TAG_RESOLUTION_UNIT, &unit );

#ifdef DEBUG
	printf( "vips_image_resolution_from_exif: seen exif tags "
		"xres = %g, yres = %g, unit = %d\n", xres, yres, unit );
#endif /*DEBUG*/

	switch( unit ) {
	case 1:
		/* No units, instead xres / yres gives the pixel aspect ratio.
		 */
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
		g_warning( "%s", _( "unknown EXIF resolution unit" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_image_resolution_from_exif: "
		"seen exif resolution %g, %g p/mm\n", xres, yres );
#endif /*DEBUG*/

	/* Don't allow negative resolution.
	 */
	image->Xres = VIPS_MAX( 0, xres );
	image->Yres = VIPS_MAX( 0, yres );

	return( 0 );
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
	const void *data;
	size_t size;
	ExifData *ed;
	VipsExifParams params;
	const char *str;

	if( !vips_image_get_typeof( image, VIPS_META_EXIF_NAME ) )
		return( 0 );
	if( vips_image_get_blob( image, VIPS_META_EXIF_NAME, &data, &size ) )
		return( -1 ); 
	if( !(ed = vips_exif_load_data_without_fix( data, size )) )
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

	/* Make sure all required fields are there before we attach the vips
	 * metadata.
	 */
	exif_data_fix( ed );

	/* Attach informational fields for what we find.
	 */
	params.image = image;
	params.ed = ed;
	exif_data_foreach_content( ed, 
		(ExifDataForeachContentFunc) vips_exif_get_content, &params );

	vips_image_set_blob_copy( image, 
		"jpeg-thumbnail-data", ed->data, ed->size );

	exif_data_free( ed );

	/* Orientation handling. ifd0 has the Orientation tag for the main
	 * image. 
	 */
	if( vips_image_get_typeof( image, "exif-ifd0-Orientation" ) != 0 &&
		!vips_image_get_string( image, 
			"exif-ifd0-Orientation", &str ) ) {
		int orientation;

		orientation = atoi( str );
		if( orientation < 1 || 
			orientation > 8 )
			orientation = 1;
		vips_image_set_int( image, VIPS_META_ORIENTATION, orientation );
	}

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
		vips_exif_entry_get_name( entry ), value );

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

/* Parse a char * into an ExifRational. We allow floats as well.
 */
static void
vips_exif_parse_rational( const char *str, ExifRational *rv )
{
	if( sscanf( str, " %u / %u ", &rv->numerator, &rv->denominator ) == 2 )
		return;
	vips_exif_double_to_rational( g_ascii_strtod( str, NULL ), rv );
}

/* Parse a char * into an ExifSRational. We allow floats as well.
 */
static void
vips_exif_parse_srational( const char *str, ExifSRational *srv )
{
	if( sscanf( str, " %d / %d ", 
		&srv->numerator, &srv->denominator ) == 2 )
		return;
	vips_exif_double_to_srational( g_ascii_strtod( str, NULL ), srv );
}

/* Does both signed and unsigned rationals from a char *.
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
		vips_exif_entry_get_name( entry ), value );

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
		vips_exif_entry_get_name( entry ), value );

	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifRational rv;

		rv = exif_get_rational( entry->data + offset, bo );
		if( rv.denominator == 0 )
			old_value = 0;
		else
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
		if( srv.denominator == 0 )
			old_value = 0;
		else
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

/* String-valued tags need special treatment, sadly.
 *
 * Strings are written in three ways: 
 *
 * 1. As ASCII, but with an 8-byte preamble giving the encoding (it's always
 * ASCII though) and the format undefined.
 * 2. As plain ASCII, with the format giving the encoding.
 * 3. As UTF16 in the MS tags.
 */

static gboolean
tag_is_encoding( ExifTag tag )
{
	return( tag == EXIF_TAG_USER_COMMENT );
}

static gboolean
tag_is_ascii( ExifTag tag )
{
	return( tag == EXIF_TAG_MAKE ||
		tag == EXIF_TAG_MODEL ||
		tag == EXIF_TAG_IMAGE_DESCRIPTION ||
		tag == EXIF_TAG_ARTIST ||
		tag == EXIF_TAG_SOFTWARE ||
		tag == EXIF_TAG_COPYRIGHT ||
		tag == EXIF_TAG_DATE_TIME ||
		tag == EXIF_TAG_DATE_TIME_ORIGINAL ||
		tag == EXIF_TAG_DATE_TIME_DIGITIZED ||
		tag == EXIF_TAG_SUB_SEC_TIME ||
		tag == EXIF_TAG_SUB_SEC_TIME_ORIGINAL ||
		tag == EXIF_TAG_SUB_SEC_TIME_DIGITIZED
#ifdef HAVE_EXIF_0_6_22
		|| tag == EXIF_TAG_CAMERA_OWNER_NAME
		|| tag == EXIF_TAG_BODY_SERIAL_NUMBER
		|| tag == EXIF_TAG_LENS_MAKE
		|| tag == EXIF_TAG_LENS_MODEL
		|| tag == EXIF_TAG_LENS_SERIAL_NUMBER
#endif
#ifdef HAVE_EXIF_0_6_23
		|| tag == EXIF_TAG_OFFSET_TIME
		|| tag == EXIF_TAG_OFFSET_TIME_ORIGINAL
		|| tag == EXIF_TAG_OFFSET_TIME_DIGITIZED
		|| tag == EXIF_TAG_GPS_LATITUDE_REF
		|| tag == EXIF_TAG_GPS_LONGITUDE_REF
		|| tag == EXIF_TAG_GPS_SATELLITES
		|| tag == EXIF_TAG_GPS_STATUS
		|| tag == EXIF_TAG_GPS_MEASURE_MODE
		|| tag == EXIF_TAG_GPS_SPEED_REF
		|| tag == EXIF_TAG_GPS_TRACK_REF
		|| tag == EXIF_TAG_GPS_IMG_DIRECTION_REF
		|| tag == EXIF_TAG_GPS_MAP_DATUM
		|| tag == EXIF_TAG_GPS_DEST_LATITUDE_REF
		|| tag == EXIF_TAG_GPS_DEST_LONGITUDE_REF
		|| tag == EXIF_TAG_GPS_DEST_BEARING_REF
		|| tag == EXIF_TAG_GPS_DEST_DISTANCE_REF
		|| tag == EXIF_TAG_GPS_DATE_STAMP
#endif
		);
}

static gboolean
tag_is_utf16( ExifTag tag )
{
	return( tag == EXIF_TAG_XP_TITLE || 
		tag == EXIF_TAG_XP_COMMENT || 
		tag == EXIF_TAG_XP_AUTHOR || 
		tag == EXIF_TAG_XP_KEYWORDS ||
		tag == EXIF_TAG_XP_SUBJECT );
}

/* Set a libexif-formatted string entry. 
 */
static void
vips_exif_alloc_string( ExifEntry *entry, unsigned long components )
{
	ExifMem *mem;

	g_assert( !entry->data );

	/* The string in the entry must be allocated with the same allocator
	 * that was used to allocate the entry itself. We can't do this
	 * because the allocator is private :( so we must assume the entry was
	 * created with the default one.
	 */
	mem = exif_mem_new_default();

	/* EXIF_FORMAT_UNDEFINED is correct for EXIF_TAG_USER_COMMENT, our 
	 * caller should change this if it wishes.
	 */
	entry->data = exif_mem_alloc( mem, components );
        entry->size = components;
        entry->components = components;
        entry->format = EXIF_FORMAT_UNDEFINED;

	VIPS_FREEF( exif_mem_unref, mem );
}

/* The final " (xx, yy, zz, kk)" part of the string (if present) was
 * added by us in _to_s(), we must remove it before setting the string 
 * back again.
 *
 * It may not be there if the user has changed the string.
 */
static char *
drop_tail( const char *data )
{
	char *str;
	char *p;

	str = g_strdup( data );

	p = str + strlen( str );
	if( p > str &&
		*g_utf8_prev_char( p ) == ')' &&
		(p = g_utf8_strrchr( str, -1, (gunichar) '(')) &&
		p > str &&
		*(p = g_utf8_prev_char( p )) == ' ' )
		*p = '\0';

	return( str );
}

/* special header required for EXIF_TAG_USER_COMMENT.
 */
#define ASCII_COMMENT "ASCII\0\0\0"

/* Write a libvips NULL-terminated utf-8 string into a entry tagged with a
 * encoding. UserComment is like this, for example.
 */
static void
vips_exif_set_string_encoding( ExifData *ed, 
	ExifEntry *entry, unsigned long component, const char *data )
{
	char *str;
	char *ascii;
	int len;

	str = drop_tail( data );

	/* libexif can only really save ASCII to things like UserComment.
	 */
	ascii = g_str_to_ascii( str, NULL );
	g_free( str );
	str = ascii;

	/* libexif comment strings are not NULL-terminated, and have an 
	 * encoding tag (always ASCII) in the first 8 bytes.
	 */
	len = strlen( str );
	vips_exif_alloc_string( entry, sizeof( ASCII_COMMENT ) - 1 + len );
	memcpy( entry->data, ASCII_COMMENT, sizeof( ASCII_COMMENT ) - 1 );
        memcpy( entry->data + sizeof( ASCII_COMMENT ) - 1, str, len );

	g_free( str );
}

/* Write a libvips NULL-terminated utf-8 string into an ASCII entry. Tags like
 * ImageDescription work like this.
 */
static void
vips_exif_set_string_ascii( ExifData *ed, 
	ExifEntry *entry, unsigned long component, const char *data )
{
	char *str;
	char *ascii;
	int len;

	str = drop_tail( data );

	/* libexif can only really save ASCII to things like UserComment.
	 */
	ascii = g_str_to_ascii( str, NULL );
	g_free( str );
	str = ascii;

	/* ASCII strings are NULL-terminated.
	 */
	len = strlen( str );
	vips_exif_alloc_string( entry, len + 1 );
        memcpy( entry->data, str, len + 1 );
        entry->format = EXIF_FORMAT_ASCII;

	g_free( str );
}

/* Write a libvips NULL-terminated utf-8 string into a utf16 entry.
 */
static void
vips_exif_set_string_utf16( ExifData *ed, 
	ExifEntry *entry, unsigned long component, const char *data )
{
	char *str;
	gunichar2 *utf16;
	glong len;

	str = drop_tail( data );

	utf16 = g_utf8_to_utf16( str, -1, NULL, &len, NULL );

	/* libexif utf16 strings are NULL-terminated.
	 */
	vips_exif_alloc_string( entry, (len + 1) * 2 );
	memcpy( entry->data, utf16, (len + 1) * 2 ); 
        entry->format = EXIF_FORMAT_BYTE;

	g_free( utf16 ); 
	g_free( str );
}

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
		exif_entry_unref( entry );

		/* libexif makes us have a special path for string-valued
		 * fields :(
		 */
		if( tag_is_encoding( tag ) ) 
			vips_exif_set_string_encoding( ed, entry, 0, data );
		else if( tag_is_ascii( tag ) ) 
			vips_exif_set_string_ascii( ed, entry, 0, data );
		else if( tag_is_utf16( tag ) )
			vips_exif_set_string_utf16( ed, entry, 0, data );
		else {
			exif_entry_initialize( entry, tag );
			fn( ed, entry, 0, data );
		}
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
		g_warning( "%s", _( "unknown EXIF resolution unit" ) );
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

/* And thumbnail. 
 */
static int
vips_exif_set_thumbnail( ExifData *ed, VipsImage *im )
{
	/* Delete any old thumbnail data. We should use the exif free func,
	 * but the memory allocator is not exposed by libexif! Hopefully they
	 * are just using free().
	 *
	 * exif.c makes this assumption too when it tries to update a
	 * thumbnail. 
	 */
	if( ed->data ) {
		free( ed->data );
		ed->data = NULL;
	}
	ed->size = 0;

	/* Update EXIF thumbnail from metadata, if any. 
	 */
	if( vips_image_get_typeof( im, "jpeg-thumbnail-data" ) ) { 
		const void *data;
		size_t size;

		if( vips_image_get_blob( im, "jpeg-thumbnail-data", 
			&data, &size ) ) 
			return( -1 );

		/* Again, we should use the exif allocator attached to this
		 * entry, but it is not exposed!
		 */
		if( size > 0 && 
			data ) { 
			ed->data = malloc( size );
			memcpy( ed->data, data, size );
			ed->size = size;
		}
	}

	return( 0 );
}

/* Skip any spaces.
 */
static const char *
skip_space( const char *p )
{
	while( p && *p == ' ' )
		p += 1;

	return( p );
}

/* Skip to the end of this non-space sequence.
 */
static const char *
skip_nonspace( const char *p )
{
	while( p && *p && *p != ' ' )
		p += 1;

	return( p );
}

/* See also vips_exif_to_s() ... keep in sync. Only the numeric types are
 * handled here, since they can be updated. For string types, we have to
 * destroy and recreate, see above. 
 */
static void
vips_exif_from_s( ExifData *ed, ExifEntry *entry, const char *value )
{
	unsigned long i;
	const char *p;
	int v;

	if( entry->format == EXIF_FORMAT_SHORT ||
		entry->format == EXIF_FORMAT_SSHORT ||
		entry->format == EXIF_FORMAT_LONG ||
		entry->format == EXIF_FORMAT_SLONG ) {
		if( entry->components >= 10 )
			return;

		p = value;
		for( i = 0; i < entry->components; i++ ) {
			if( !(p = skip_space( p )) )
			       break;	

			v = atof( p );
			vips_exif_set_int( ed, entry, i, &v );

			p = skip_nonspace( p );
		}
	}
	else if( entry->format == EXIF_FORMAT_RATIONAL ||
		entry->format == EXIF_FORMAT_SRATIONAL ) {
		if( entry->components >= 10 )
			return;

		p = value;
		for( i = 0; i < entry->components; i++ ) {
			if( !(p = skip_space( p )) )
			       break;	

			vips_exif_set_rational( ed, entry, i, (void *) p );

			p = skip_nonspace( p );
		}
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
		g_warning( _( "bad exif meta \"%s\"" ), field );
		return( NULL ); 
	}

	p = field + strlen( "exif-ifd" );
	ifd = atoi( p ); 

	for( ; isdigit( *p ); p++ )
		;
	if( *p != '-' ) {
		g_warning( _( "bad exif meta \"%s\"" ), field );
		return( NULL ); 
	}

	/* GPSVersionID is tag 0 (the error return) so we have to
	 * test the name too.
	 */
	if( !(tag = exif_tag_from_name( p + 1 )) &&
		strcmp( p + 1, "GPSVersionID" ) != 0 ) {
		g_warning( _( "bad exif meta \"%s\"" ), field );
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
	VipsBuf vips_name_buf = VIPS_BUF_STATIC( vips_name_txt );

	const char *vips_name;
	const char *vips_value;

	if( !(tag_name = vips_exif_entry_get_name( entry )) )
		return;

	vips_buf_appendf( &vips_name_buf, "exif-ifd%d-%s", 
		exif_entry_get_ifd( entry ), tag_name );
	vips_name = vips_buf_all( &vips_name_buf );

	/* Is there a image metadata item for this tag?
	 */
	vips_value = NULL;
	if( vips_image_get_typeof( ve->image, vips_name ) ) {
		/* No easy way to return an error code from here, sadly.
		 */
		if( vips_image_get_string( ve->image, vips_name, &vips_value ) )
			g_warning( _( "bad exif meta \"%s\"" ), vips_name );
	}

	/* Does this field exist on the image? If not, schedule it for
	 * removal.
	 */
	if( !vips_value )
		ve->to_remove = g_slist_prepend( ve->to_remove, entry );

	/* Orientation is really set from the vips
	 * VIPS_META_ORIENTATION tag. If that's been deleted, we must delete
	 * any matching EXIF tags too.
	 */
	if( strcmp( tag_name, "Orientation" ) == 0 &&
		vips_value )
		ve->to_remove = g_slist_prepend( ve->to_remove, entry );

	/* If this is a string tag with a new value, we must also remove it 
	 * ready for recreation, see the comment below.
	 */
	if( vips_value &&
		(tag_is_encoding( entry->tag ) ||
		 tag_is_ascii( entry->tag ) ||
		 tag_is_utf16( entry->tag )) ) {
		char value_txt[256];
		VipsBuf value = VIPS_BUF_STATIC( value_txt );

		/* Render the original exif-data value to a string and see
		 * if the user has changed it. If they have, remove it ready
		 * for re-adding.
		 *
		 * Leaving it there prevents it being recreated.
		 */
		vips_exif_to_s( ve->ed, entry, &value );
		if( strcmp( vips_buf_all( &value ), vips_value ) != 0 )
			ve->to_remove = g_slist_prepend( ve->to_remove, entry );
	}
}

static void *
vips_exif_exif_remove( ExifEntry *entry, VipsExifRemove *ve, void *b )
{
#ifdef DEBUG
{
	const char *tag_name;
	char vips_name_txt[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( vips_name_txt );

	tag_name = vips_exif_entry_get_name( entry );
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

	/* If this exif came from the image (rather than being an exif block we
	 * have made afresh), then any fields which are in the block but not on
	 * the image must have been deliberately removed. Remove them from the
	 * block as well.
	 *
	 * Any string-valued fields (eg. comment etc.) which exist as libvips 
	 * metadata tags with changed  whose values have changed must also be 
	 * removed.
	 *
	 * libexif does not allow you to change string lengths (you must make
	 * new tags) so we have to remove ready to re-add.
	 */
	if( vips_image_get_typeof( image, VIPS_META_EXIF_NAME ) ) {
		ve.image = image;
		ve.ed = ed;
		exif_data_foreach_content( ed, 
			(ExifDataForeachContentFunc) vips_exif_exif_content, 
			&ve );
	}

	/* Walk the image and add any exif- that's set in image metadata.
	 */
	vips_image_map( image, vips_exif_image_field, ed );
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

	/* Update the thumbnail.
	 */
	if( vips_exif_set_thumbnail( ed, image ) ) {
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
		(VipsCallbackFn) vips_area_free_cb, data, length );

	exif_data_free( ed );

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
