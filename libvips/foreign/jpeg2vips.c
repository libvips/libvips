/* wrap jpeg library for read
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 12/11/04
 *	- better demand size choice for eval
 * 30/6/05 JC
 *	- update im_error()/im_warn()
 *	- now loads and saves exif data
 * 30/7/05
 * 	- now loads ICC profiles
 * 	- now saves ICC profiles from the VIPS header
 * 24/8/05
 * 	- jpeg load sets vips xres/yres from exif, if possible
 * 	- jpeg save sets exif xres/yres from vips, if possible
 * 29/8/05
 * 	- cut from old vips_jpeg.c
 * 13/10/06
 * 	- add </libexif/ prefix if required
 * 11/2/08
 * 	- spot CMYK jpegs and set Type
 * 	- spot Adobe CMYK JPEG and invert ink density
 * 15/2/08
 * 	- added "shrink" parameter
 * 16/6/09
 *	- added "fail" option ... fail on any warnings
 * 12/10/09
 * 	- also set scale_num on shrink (thanks Guido)
 * 4/2/10
 * 	- gtkdoc
 * 4/12/10
 * 	- attach the jpeg thumbnail and multiscan fields (thanks Mike)
 * 21/2/10
 * 	- only accept the first APP1 block which starts "Exif..." as exif
 * 	  data, some jpegs seem to have several APP1s, argh
 * 20/4/2011
 * 	- added im_bufjpeg2vips()
 * 12/10/2011
 * 	- read XMP data
 * 3/11/11
 * 	- attach exif tags as coded values 
 * 24/11/11
 * 	- turn into a set of read fns ready to be called from a class
 * 9/1/12
 * 	- read jfif resolution as well as exif
 * 19/2/12
 * 	- switch to lazy reading
 * 7/8/12
 * 	- note EXIF resolution unit in VIPS_META_RESOLUTION_UNIT
 * 16/11/12
 * 	- tag exif fields with their ifd
 * 	- attach rationals as a/b, don't convert to double
 * 21/11/12
 * 	- don't insist exif must have data
 * 	- attach IPCT data (app13), thanks Gary
 * 6/7/13
 * 	- null-terminate exif strings, thanks Mike
 * 24/2/14
 * 	- don't write to our input buffer, thanks Lovell
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

#ifdef HAVE_JPEG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

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
#endif /*HAVE_EXIF*/

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "jpeg.h"
#include "vipsjpeg.h"

/* Stuff we track during a read.
 */
typedef struct _ReadJpeg {
	VipsImage *out;

	/* Shrink by this much during load. 1, 2, 4, 8.
	 */
	int shrink;

	/* Fail on warnings.
	 */
	gboolean fail;

	/* Use a read behind buffer.
	 */
	gboolean readbehind; 

	/* Used for file input only.
	 */
	char *filename;

	struct jpeg_decompress_struct cinfo;
        ErrorManager eman;
	gboolean invert_pels;

	/* Set if we need to finish the decompress.
	 */
	gboolean decompressing;

	/* Track the y pos during a read with this.
	 */
	int y_pos;
} ReadJpeg;

static int
readjpeg_free( ReadJpeg *jpeg )
{
	int result;

	result = 0;

	if( jpeg->eman.pub.num_warnings != 0 ) {
		if( jpeg->fail ) {
			vips_error( "VipsJpeg", "%s", vips_error_buffer() );
			result = -1;
		}
		else {
			vips_warn( "VipsJpeg", 
				_( "read gave %ld warnings" ), 
				jpeg->eman.pub.num_warnings );
			vips_warn( NULL, "%s", vips_error_buffer() );
		}

		/* Make the message only appear once.
		 */
		jpeg->eman.pub.num_warnings = 0;
	}

	if( jpeg->decompressing ) {
		/* jpeg_finish_decompress() can fail ... catch any errors.
		 */
		if( !setjmp( jpeg->eman.jmp ) ) 
			jpeg_finish_decompress( &jpeg->cinfo );

		jpeg->decompressing = FALSE;
	}

	VIPS_FREEF( fclose, jpeg->eman.fp );
	VIPS_FREE( jpeg->filename );
	jpeg->eman.fp = NULL;

	/* I don't think this can fail.
	 */
	jpeg_destroy_decompress( &jpeg->cinfo );

	return( result );
}

static void
readjpeg_close( VipsObject *object, ReadJpeg *jpeg )
{
	(void) readjpeg_free( jpeg );
}

static ReadJpeg *
readjpeg_new( VipsImage *out, int shrink, gboolean fail, gboolean readbehind )
{
	ReadJpeg *jpeg;

	if( !(jpeg = VIPS_NEW( out, ReadJpeg )) )
		return( NULL );

	jpeg->out = out;
	jpeg->shrink = shrink;
	jpeg->fail = fail;
	jpeg->readbehind = readbehind;
	jpeg->filename = NULL;
	jpeg->decompressing = FALSE;

        jpeg->cinfo.err = jpeg_std_error( &jpeg->eman.pub );
	jpeg->eman.pub.error_exit = vips__new_error_exit;
	jpeg->eman.pub.output_message = vips__new_output_message;
	jpeg->eman.fp = NULL;

	jpeg->y_pos = 0;

	/* jpeg_create_decompress() can fail on some sanity checks. Don't
	 * readjpeg_free() since we don't want to jpeg_destroy_decompress().
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( NULL );

        jpeg_create_decompress( &jpeg->cinfo );

	g_signal_connect( out, "close", 
		G_CALLBACK( readjpeg_close ), jpeg ); 

	return( jpeg );
}

/* Set input to a file.
 */
static int
readjpeg_file( ReadJpeg *jpeg, const char *filename )
{
	jpeg->filename = g_strdup( filename );
        if( !(jpeg->eman.fp = vips__file_open_read( filename, NULL, FALSE )) ) 
                return( -1 );
        jpeg_stdio_src( &jpeg->cinfo, jpeg->eman.fp );

	return( 0 );
}

#ifdef HAVE_EXIF
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

void
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
#endif /*HAVE_EXIF*/

#ifdef HAVE_EXIF
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
 * Keep in sync with vips_exif_from_s() in vips2jpeg.
 */
static void
vips_exif_to_s(  ExifData *ed, ExifEntry *entry, VipsBuf *buf )
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

typedef struct _VipsExif {
	VipsImage *image;
	ExifData *ed;
} VipsExif;

static void
attach_exif_entry( ExifEntry *entry, VipsExif *ve )
{
	char name_txt[256];
	VipsBuf name = VIPS_BUF_STATIC( name_txt );
	char value_txt[256];
	VipsBuf value = VIPS_BUF_STATIC( value_txt );

	vips_buf_appendf( &name, "exif-ifd%d-%s", 
		exif_entry_get_ifd( entry ),
		exif_tag_get_title( entry->tag ) );
	vips_exif_to_s( ve->ed, entry, &value ); 

	/* Can't do anything sensible with the error return.
	 */
	(void) vips_image_set_string( ve->image, 
		vips_buf_all( &name ), vips_buf_all( &value ) );
}

static void
attach_exif_content( ExifContent *content, VipsExif *ve )
{
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) attach_exif_entry, ve );
}

static int
get_entry_double( ExifData *ed, int ifd, ExifTag tag, double *out )
{
	ExifEntry *entry;

	if( !(entry = exif_content_get_entry( ed->ifd[ifd], tag )) ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_double( ed, entry, 0, out ) );
}

static int
get_entry_int( ExifData *ed, int ifd, ExifTag tag, int *out )
{
	ExifEntry *entry;

	if( !(entry = exif_content_get_entry( ed->ifd[ifd], tag )) ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_int( ed, entry, 0, out ) );
}

static void
res_from_exif( VipsImage *im, ExifData *ed )
{
	double xres, yres;
	int unit;

	/* The main image xres/yres are in ifd0. ifd1 has xres/yres of the
	 * image thumbnail, if any.
	 */
	if( get_entry_double( ed, 0, EXIF_TAG_X_RESOLUTION, &xres ) ||
		get_entry_double( ed, 0, EXIF_TAG_Y_RESOLUTION, &yres ) ||
		get_entry_int( ed, 0, EXIF_TAG_RESOLUTION_UNIT, &unit ) ) {
		vips_warn( "VipsJpeg", 
			"%s", _( "error reading resolution" ) );
		return;
	}

#ifdef DEBUG
	printf( "res_from_exif: seen exif tags "
		"xres = %g, yres = %g, unit = %d\n", xres, yres, unit );
#endif /*DEBUG*/

	switch( unit ) {
	case 2:
		/* In inches.
		 */
		xres /= 25.4;
		yres /= 25.4;
		vips_image_set_string( im, 
			VIPS_META_RESOLUTION_UNIT, "in" );
		break;

	case 3:
		/* In cm.
		 */
		xres /= 10.0;
		yres /= 10.0;
		vips_image_set_string( im, 
			VIPS_META_RESOLUTION_UNIT, "cm" );
		break;

	default:
		vips_warn( "VipsJpeg", 
			"%s", _( "unknown EXIF resolution unit" ) );
		return;
	}

#ifdef DEBUG
	printf( "res_from_exif: seen exif resolution %g, %g p/mm\n",
		       xres, yres );
#endif /*DEBUG*/

	im->Xres = xres;
	im->Yres = yres;
}

static int
attach_thumbnail( VipsImage *im, ExifData *ed )
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
#endif /*HAVE_EXIF*/

static int
parse_exif( VipsImage *im, void *data, int data_length )
{
#ifdef HAVE_EXIF
{
	ExifData *ed;
	VipsExif ve;

	if( !(ed = exif_data_new_from_data( data, data_length )) )
		return( -1 );

#ifdef DEBUG_VERBOSE
	show_tags( ed );
	show_values( ed );
#endif /*DEBUG_VERBOSE*/

	/* Attach informational fields for what we find.

		FIXME ... better to have this in the UI layer?

		Or we could attach non-human-readable tags here (int, 
		double etc) and then move the human stuff to the UI 
		layer?

	 */
	ve.image = im;
	ve.ed = ed;
	exif_data_foreach_content( ed, 
		(ExifDataForeachContentFunc) attach_exif_content, &ve );

	/* Look for resolution fields and use them to set the VIPS 
	 * xres/yres fields.
	 */
	res_from_exif( im, ed );

	attach_thumbnail( im, ed );

	exif_data_free( ed );
}
#endif /*HAVE_EXIF*/

	return( 0 );
}

static int
attach_blob( VipsImage *im, const char *field, void *data, int data_length )
{
	char *data_copy;

	/* Only use the first one.
	 */
	if( vips_image_get_typeof( im, field ) ) {
#ifdef DEBUG
		printf( "attach_blob: second %s block, ignoring\n", field );
#endif /*DEBUG*/

		return( 0 );
	}

#ifdef DEBUG
	printf( "attach_blob: attaching %d bytes of %s\n", data_length, field );
#endif /*DEBUG*/

	/* Always attach a copy of the unparsed exif data.
	 */
	if( !(data_copy = vips_malloc( NULL, data_length )) )
		return( -1 );
	memcpy( data_copy, data, data_length );
	vips_image_set_blob( im, field, 
		(VipsCallbackFn) vips_free, data_copy, data_length );

	return( 0 );
}

/* Number of app2 sections we can capture. Each one can be 64k, so 6400k should
 * be enough for anyone (haha).
 */
#define MAX_APP2_SECTIONS (100)

/* Read a cinfo to a VIPS image. Set invert_pels if the pixel reader needs to
 * do 255-pel.
 */
static int
read_jpeg_header( ReadJpeg *jpeg, VipsImage *out )
{
	struct jpeg_decompress_struct *cinfo = &jpeg->cinfo;

	jpeg_saved_marker_ptr p;
	VipsInterpretation interpretation;
	double xres, yres;

	/* Capture app2 sections here for assembly.
	 */
	void *app2_data[MAX_APP2_SECTIONS] = { 0 };
	size_t app2_data_length[MAX_APP2_SECTIONS] = { 0 };
	size_t data_length;
	int i;

	/* Read JPEG header. libjpeg will set out_color_space sanely for us 
	 * for YUV YCCK etc.
	 */
	jpeg_read_header( cinfo, TRUE );
	cinfo->scale_denom = jpeg->shrink;
	cinfo->scale_num = 1;
	jpeg_calc_output_dimensions( cinfo );

	jpeg->invert_pels = FALSE;
	switch( cinfo->out_color_space ) {
	case JCS_GRAYSCALE:
		interpretation = VIPS_INTERPRETATION_B_W;
		break;

	case JCS_CMYK:
		interpretation = VIPS_INTERPRETATION_CMYK;
		/* Photoshop writes CMYK JPEG inverted :-( Maybe this is a
		 * way to spot photoshop CMYK JPGs.
		 */
		if( cinfo->saw_Adobe_marker ) 
			jpeg->invert_pels = TRUE;
		break;

	case JCS_RGB:
	default:
		interpretation = VIPS_INTERPRETATION_sRGB;
		break;
	}

	/* Get the jfif resolution. exif may overwrite this later.
	 */
	xres = 1.0;
	yres = 1.0;
	if( cinfo->saw_JFIF_marker &&
		cinfo->X_density != 1U && 
		cinfo->Y_density != 1U ) {
#ifdef DEBUG
		printf( "read_jpeg_header: seen jfif _density %d, %d\n",
			cinfo->X_density, cinfo->Y_density );
#endif /*DEBUG*/

		switch( cinfo->density_unit ) {
		case 1:
			/* Pixels per inch.
			 */
			xres = cinfo->X_density / 25.4;
			yres = cinfo->Y_density / 25.4;
			break;

		case 2:
			/* Pixels per cm.
			 */
			xres = cinfo->X_density / 10.0;
			yres = cinfo->Y_density / 10.0;
			break;

		default:
			vips_warn( "VipsJpeg", 
				"%s", _( "unknown JFIF resolution unit" ) );
			break;
		}

#ifdef DEBUG
		printf( "read_jpeg_header: seen jfif resolution %g, %g p/mm\n",
			       xres, yres );
#endif /*DEBUG*/
	}

	/* Set VIPS header.
	 */
	vips_image_init_fields( out,
		cinfo->output_width, cinfo->output_height,
		cinfo->output_components,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		interpretation,
		xres, yres );

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	/* Interlaced jpegs need lots of memory to read, so our caller needs
	 * to know.
	 */
	(void) vips_image_set_int( out, "jpeg-multiscan", 
		jpeg_has_multiple_scans( cinfo ) );

	/* Look for EXIF and ICC profile.
	 */
	for( p = cinfo->marker_list; p; p = p->next ) {
#ifdef DEBUG
{
		printf( "read_jpeg_header: seen %d bytes of APP%d\n",
			p->data_length,
			p->marker - JPEG_APP0 );

		for( i = 0; i < 10; i++ ) 
			printf( "\t%d) '%c' (%d)\n", 
				i, p->data[i], p->data[i] );
}
#endif /*DEBUG*/

		switch( p->marker ) {
		case JPEG_APP0 + 1:
			/* Possible EXIF or XMP data.
			 */
			if( p->data_length > 4 &&
				vips_isprefix( "Exif", (char *) p->data ) ) {
				if( parse_exif( out, 
					p->data, p->data_length ) ||
					attach_blob( out, VIPS_META_EXIF_NAME, 
						p->data, p->data_length ) )
				return( -1 );
			}

			if( p->data_length > 4 &&
				vips_isprefix( "http", (char *) p->data ) &&
				attach_blob( out, VIPS_META_XMP_NAME, 
					p->data, p->data_length ) )
				return( -1 );

			break;

		case JPEG_APP0 + 2:
			/* Possible ICC profile.
			 */
			if( p->data_length > 14 &&
				vips_isprefix( "ICC_PROFILE", 
					(char *) p->data ) ) {
				/* cur_marker numbers from 1, according to
				 * spec.
				 */
				int cur_marker = p->data[12] - 1;

				if( cur_marker >= 0 &&
					cur_marker < MAX_APP2_SECTIONS ) {
					app2_data[cur_marker] = p->data + 14;
					app2_data_length[cur_marker] = 
						p->data_length - 14;
				}
			}
			break;

		case JPEG_APP0 + 13:
			/* Possible IPCT data block.
			 */
			if( p->data_length > 5 &&
				vips_isprefix( "Photo", (char *) p->data ) &&
				attach_blob( out, VIPS_META_IPCT_NAME,
					p->data, p->data_length ) )
				return( -1 );
			break;

		default:
			break;
		}
	}

	/* Assemble ICC sections.
	 */
	data_length = 0;
	for( i = 0; i < MAX_APP2_SECTIONS && app2_data[i]; i++ )
		data_length += app2_data_length[i];
	if( data_length ) {
		unsigned char *data;
		int p;

#ifdef DEBUG
		printf( "read_jpeg_header: assembled %zd byte ICC profile\n",
			data_length );
#endif /*DEBUG*/

		if( !(data = vips_malloc( NULL, data_length )) ) 
			return( -1 );

		p = 0;
		for( i = 0; i < MAX_APP2_SECTIONS && app2_data[i]; i++ ) {
			memcpy( data + p, app2_data[i], app2_data_length[i] );
			p += app2_data_length[i];
		}

		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) vips_free, data, data_length );
	}

	return( 0 );
}

static int
read_jpeg_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	ReadJpeg *jpeg = (ReadJpeg *) a;
	struct jpeg_decompress_struct *cinfo = &jpeg->cinfo;
	int sz = cinfo->output_width * cinfo->output_components;

	int y;

#ifdef DEBUG
	printf( "read_jpeg_generate: line %d, %d rows\n", 
		r->top, r->height );
#endif /*DEBUG*/

	VIPS_GATE_START( "read_jpeg_generate: work" );

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert( r->left == 0 );
	g_assert( r->width == or->im->Xsize );
	g_assert( VIPS_RECT_BOTTOM( r ) <= or->im->Ysize );

	/* Tiles should always be on a 8-pixel boundary.
	 */
	g_assert( r->top % 8 == 0 );

	/* Tiles should always be a strip in height, unless it's the final
	 * strip.
	 */
	g_assert( r->height == VIPS_MIN( 8, or->im->Ysize - r->top ) ); 

	/* And check that y_pos is correct. It should be, since we are inside
	 * a vips_sequential().
	 */
	g_assert( r->top == jpeg->y_pos ); 

	/* Here for longjmp() from vips__new_error_exit().
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		JSAMPROW row_pointer[1];

		row_pointer[0] = (JSAMPLE *) 
			VIPS_REGION_ADDR( or, 0, r->top + y );

		jpeg_read_scanlines( cinfo, &row_pointer[0], 1 );

		if( jpeg->invert_pels ) {
			int x;

			for( x = 0; x < sz; x++ )
				row_pointer[0][x] = 255 - row_pointer[0][x];
		}

		jpeg->y_pos += 1; 
	}

	VIPS_GATE_STOP( "read_jpeg_generate: work" );

	return( 0 );
}

/* Read a cinfo to a VIPS image.
 */
static int
read_jpeg_image( ReadJpeg *jpeg, VipsImage *out )
{
	struct jpeg_decompress_struct *cinfo = &jpeg->cinfo;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	/* Here for longjmp() from vips__new_error_exit().
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	t[0] = vips_image_new();
	if( read_jpeg_header( jpeg, t[0] ) )
		return( -1 );

	/* Set decompressing to make readjpeg_free() call 
	 * jpeg_stop_decompress().
	 */
	jpeg_start_decompress( cinfo );
	jpeg->decompressing = TRUE;

#ifdef DEBUG
	printf( "read_jpeg_image: starting decompress\n" );
#endif /*DEBUG*/

	if( vips_image_generate( t[0], 
		NULL, read_jpeg_generate, NULL, 
		jpeg, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", 8,
			"access", jpeg->readbehind ? 
				VIPS_ACCESS_SEQUENTIAL : 
				VIPS_ACCESS_SEQUENTIAL_UNBUFFERED,
			NULL ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

/* Read a JPEG file into a VIPS image.
 */
int
vips__jpeg_read_file( const char *filename, VipsImage *out, 
	gboolean header_only, int shrink, gboolean fail, gboolean readbehind )
{
	ReadJpeg *jpeg;
	int result;

	if( !(jpeg = readjpeg_new( out, shrink, fail, readbehind )) )
		return( -1 );

	/* Here for longjmp() from vips__new_error_exit() during startup.
	 */
	if( setjmp( jpeg->eman.jmp ) ) {
		(void) readjpeg_free( jpeg );

		return( -1 );
	}

	/* Set input to file.
	 */
	if( readjpeg_file( jpeg, filename ) ) {
		(void) readjpeg_free( jpeg );

		return( -1 );
	}

	/* Need to read in APP1 (EXIF metadata), APP2 (ICC profile), APP13
	 * (photoshop IPCT).
	 */
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 2, 0xffff );
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 13, 0xffff );

	/* Convert!
	 */
	if( header_only )
		result = read_jpeg_header( jpeg, out );
	else
		result = read_jpeg_image( jpeg, out );

	/* Don't call readjpeg_free(), we're probably still live.
	 */

	return( result );
}

/* Just like the above, but we read from a memory buffer.
 */
typedef struct {
	/* Public jpeg fields.
	 */
	struct jpeg_source_mgr pub;

	/* Private stuff during read.
	 */
	gboolean start_of_file;	/* have we gotten any data yet? */
	JOCTET *buf;
	size_t len;
} InputBuffer;

/*
 * Initialize source --- called by jpeg_read_header
 * before any data is actually read.
 */

static void
init_source (j_decompress_ptr cinfo)
{
  InputBuffer *src = (InputBuffer *) cinfo->src;

  /* We reset the empty-input-file flag for each image,
   * but we don't clear the input buffer.
   * This is correct behavior for reading a series of images from one source.
   */
  src->start_of_file = TRUE;
}

/*
 * Fill the input buffer --- called whenever buffer is emptied.
 *
 * In typical applications, this should read fresh data into the buffer
 * (ignoring the current state of next_input_byte & bytes_in_buffer),
 * reset the pointer & count to the start of the buffer, and return TRUE
 * indicating that the buffer has been reloaded.  It is not necessary to
 * fill the buffer entirely, only to obtain at least one more byte.
 *
 * There is no such thing as an EOF return.  If the end of the file has been
 * reached, the routine has a choice of ERREXIT() or inserting fake data into
 * the buffer.  In most cases, generating a warning message and inserting a
 * fake EOI marker is the best course of action --- this will allow the
 * decompressor to output however much of the image is there.  However,
 * the resulting error message is misleading if the real problem is an empty
 * input file, so we handle that case specially.
 *
 * In applications that need to be able to suspend compression due to input
 * not being available yet, a FALSE return indicates that no more data can be
 * obtained right now, but more may be forthcoming later.  In this situation,
 * the decompressor will return to its caller (with an indication of the
 * number of scanlines it has read, if any).  The application should resume
 * decompression after it has loaded more data into the input buffer.  Note
 * that there are substantial restrictions on the use of suspension --- see
 * the documentation.
 *
 * When suspending, the decompressor will back up to a convenient restart point
 * (typically the start of the current MCU). next_input_byte & bytes_in_buffer
 * indicate where the restart point will be if the current call returns FALSE.
 * Data beyond this point must be rescanned after resumption, so move it to
 * the front of the buffer rather than discarding it.
 */

static boolean
fill_input_buffer (j_decompress_ptr cinfo)
{
  static const JOCTET eoi_buffer[4] = {
    (JOCTET) 0xFF, (JOCTET) JPEG_EOI, 0, 0
  };

  InputBuffer *src = (InputBuffer *) cinfo->src;

  if (src->start_of_file) {
    src->pub.next_input_byte = src->buf;
    src->pub.bytes_in_buffer = src->len;
  }
  else {
    WARNMS(cinfo, JWRN_JPEG_EOF);
    src->pub.next_input_byte = eoi_buffer;
    src->pub.bytes_in_buffer = 2;
    src->start_of_file = FALSE;
  }

  return TRUE;
}

/*
 * Skip data --- used to skip over a potentially large amount of
 * uninteresting data (such as an APPn marker).
 *
 * Writers of suspendable-input applications must note that skip_input_data
 * is not granted the right to give a suspension return.  If the skip extends
 * beyond the data currently in the buffer, the buffer can be marked empty so
 * that the next read will cause a fill_input_buffer call that can suspend.
 * Arranging for additional bytes to be discarded before reloading the input
 * buffer is the application writer's problem.
 */

static void
skip_input_data (j_decompress_ptr cinfo, long num_bytes)
{
  InputBuffer *src = (InputBuffer *) cinfo->src;

  /* Just skip fwd.
   */
  if (num_bytes > 0) {
    src->pub.next_input_byte += (size_t) num_bytes;
    src->pub.bytes_in_buffer -= (size_t) num_bytes;
  }
}

/*
 * An additional method that can be provided by data source modules is the
 * resync_to_restart method for error recovery in the presence of RST markers.
 * For the moment, this source module just uses the default resync method
 * provided by the JPEG library.  That method assumes that no backtracking
 * is possible.
 */

/*
 * Terminate source --- called by jpeg_finish_decompress
 * after all data has been read.  Often a no-op.
 *
 * NB: *not* called by jpeg_abort or jpeg_destroy; surrounding
 * application must deal with any cleanup that should happen even
 * for error exit.
 */

static void
term_source (j_decompress_ptr cinfo)
{
  /* no work necessary here */
}

/*
 * Prepare for input from a memory buffer. The caller needs to free the
 * buffer after decompress is done, we don't take ownership.
 */

static void
readjpeg_buffer (ReadJpeg *jpeg, void *buf, size_t len)
{
  j_decompress_ptr cinfo = &jpeg->cinfo;
  InputBuffer *src;

  /* The source object and input buffer are made permanent so that a series
   * of JPEG images can be read from the same file by calling jpeg_stdio_src
   * only before the first one.  (If we discarded the buffer at the end of
   * one image, we'd likely lose the start of the next one.)
   * This makes it unsafe to use this manager and a different source
   * manager serially with the same JPEG object.  Caveat programmer.
   */
  if (cinfo->src == NULL) {	/* first time for this JPEG object? */
    cinfo->src = (struct jpeg_source_mgr *)
      (*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_PERMANENT,
				  sizeof(InputBuffer));
    src = (InputBuffer *) cinfo->src;
    src->buf = buf;
    src->len = len;
  }

  src = (InputBuffer *) cinfo->src;
  src->pub.init_source = init_source;
  src->pub.fill_input_buffer = fill_input_buffer;
  src->pub.skip_input_data = skip_input_data;
  src->pub.resync_to_restart = jpeg_resync_to_restart; /* use default method */
  src->pub.term_source = term_source;
  src->pub.bytes_in_buffer = 0; /* forces fill_input_buffer on first read */
  src->pub.next_input_byte = NULL; /* until buffer loaded */
}

int
vips__jpeg_read_buffer( void *buf, size_t len, VipsImage *out, 
	gboolean header_only, int shrink, int fail, gboolean readbehind )
{
	ReadJpeg *jpeg;
	int result;

	if( !(jpeg = readjpeg_new( out, shrink, fail, readbehind )) )
		return( -1 );

	if( setjmp( jpeg->eman.jmp ) ) {
		(void) readjpeg_free( jpeg );

		return( -1 );
	}

	/* Set input to buffer.
	 */
	readjpeg_buffer( jpeg, buf, len );

	/* Need to read in APP1 (EXIF metadata) and APP2 (ICC profile).
	 */
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 2, 0xffff );

	/* Convert!
	 */
	if( header_only )
		result = read_jpeg_header( jpeg, out );
	else
		result = read_jpeg_image( jpeg, out );

	/* Don't call readjpeg_free(), we're probably still live.
	 */

	return( result );
}

int
vips__isjpeg( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) )
		if( (int) buf[0] == 0xff && (int) buf[1] == 0xd8 )
			return( 1 );

	return( 0 );
}

#endif /*HAVE_JPEG*/
