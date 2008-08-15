/* Convert 1 or 3-band 8-bit VIPS images to/from JPEG.
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
#define DEBUG
#define DEBUG_VERBOSE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifndef HAVE_JPEG

#include <vips/vips.h>

int
im_jpeg2vips( const char *name, IMAGE *out )
{
	im_error( "im_jpeg2vips", _( "JPEG support disabled" ) );

	return( -1 );
}

void 
im__jpeg_register( void )
{
}

#else /*HAVE_JPEG*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <assert.h>

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
#include <vips/vbuf.h>
#include <vips/internal.h>

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Define a new error handler for when we bomb out.
 */
typedef struct {
	/* Public fields.
	 */
	struct jpeg_error_mgr pub;

	/* Private stuff for us.
	 */
	jmp_buf jmp;		/* longjmp() here to get back to VIPS */
	FILE *fp;		/* fclose() if non-NULL */
} ErrorManager;

/* New output message method - send to VIPS.
 */
METHODDEF(void)
new_output_message( j_common_ptr cinfo )
{
	char buffer[JMSG_LENGTH_MAX];

	(*cinfo->err->format_message)( cinfo, buffer );
	im_error( "vips_jpeg", _( "%s" ), buffer );

#ifdef DEBUG
	printf( "vips_jpeg.c: new_output_message: \"%s\"\n", buffer );
#endif /*DEBUG*/
}

/* New error_exit handler.
 */
METHODDEF(void)
new_error_exit( j_common_ptr cinfo )
{
	ErrorManager *eman = (ErrorManager *) cinfo->err;

#ifdef DEBUG
	printf( "vips_jpeg.c: new_error_exit\n" );
#endif /*DEBUG*/

	/* Close the fp if necessary.
	 */
	if( eman->fp ) {
		(void) fclose( eman->fp );
		eman->fp = NULL;
	}

	/* Send the error message to VIPS. This method is overridden above.
	 */
	(*cinfo->err->output_message)( cinfo );

	/* Jump back.
	 */
	longjmp( eman->jmp, 1 );
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
        exif_content_foreach_entry( content, show_entry, client );
        printf( "-\n" );
}

void
show_values( ExifData *data )
{
        ExifByteOrder order;

        order = exif_data_get_byte_order( data );
        printf( "EXIF tags in '%s' byte order\n", 
		exif_byte_order_get_name( order ) );

	printf( "%-20.20s", "Tag" );
        printf( "|" );
	printf( "%-58.58s", "Value" );
        printf( "\n" );

        exif_data_foreach_content( data, show_ifd, NULL );

        if( data->size ) 
                printf( "contains thumbnail of %d bytes\n", data->size );
}
#endif /*DEBUG_VERBOSE*/
#endif /*HAVE_EXIF*/

#ifdef HAVE_EXIF
static void
attach_exif_entry( ExifEntry *entry, IMAGE *im )
{
	char name_text[256];
	VBuf name;
	char value_text[256];
	VBuf value;
	char exif_value[256];

	im_buf_init_static( &name, name_text, 256 );
	im_buf_init_static( &value, value_text, 256 );

	im_buf_appendf( &name, "exif-%s", exif_tag_get_title( entry->tag ) );
	im_buf_appendf( &value, "%s (%s, %d bytes)", 
		exif_entry_get_value( entry, exif_value, 256 ),
		exif_format_get_name( entry->format ),
		entry->size );

	/* Can't do anything sensible with the error return.
	 */
	(void) im_meta_set_string( im, 
		im_buf_all( &name ), im_buf_all( &value ) );
}

static void
attach_exif_content( ExifContent *content, IMAGE *im )
{
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) attach_exif_entry, im );
}

/* Just find the first occurence of the tag (is this correct?)
 */
static ExifEntry *
find_entry( ExifData *ed, ExifTag tag )
{
	int i;

	for( i = 0; i < EXIF_IFD_COUNT; i++ ) {
		ExifEntry *entry;

		if( (entry = exif_content_get_entry( ed->ifd[i], tag )) )
			return( entry );
	}

	return( NULL );
}

static int
get_entry_rational( ExifData *ed, ExifTag tag, double *out )
{
	ExifEntry *entry;
	ExifRational rational;

	if( !(entry = find_entry( ed, tag )) ||
		entry->format != EXIF_FORMAT_RATIONAL ||
		entry->components != 1 )
		return( -1 );

	rational = exif_get_rational( entry->data,
		exif_data_get_byte_order( ed ) );

	*out = (double) rational.numerator / rational.denominator;

	return( 0 );
}

static int
get_entry_short( ExifData *ed, ExifTag tag, int *out )
{
	ExifEntry *entry;

	if( !(entry = find_entry( ed, tag )) ||
		entry->format != EXIF_FORMAT_SHORT ||
		entry->components != 1 )
		return( -1 );

	*out = exif_get_short( entry->data,
		exif_data_get_byte_order( ed ) );

	return( 0 );
}

static void
set_vips_resolution( IMAGE *im, ExifData *ed )
{
	double xres, yres;
	int unit;

	if( get_entry_rational( ed, EXIF_TAG_X_RESOLUTION, &xres ) ||
		get_entry_rational( ed, EXIF_TAG_Y_RESOLUTION, &yres ) ||
		get_entry_short( ed, EXIF_TAG_RESOLUTION_UNIT, &unit ) ) {
		im_warn( "im_jpeg2vips", _( "error reading resolution" ) );
		return;
	}

	switch( unit ) {
	case 2:
		/* In inches.
		 */
		xres /= 25.4;
		yres /= 25.4;
		break;

	case 3:
		/* In cm.
		 */
		xres /= 10.0;
		yres /= 10.0;
		break;

	default:
		im_warn( "im_jpeg2vips", _( "bad resolution unit" ) );
		return;
	}

	im->Xres = xres;
	im->Yres = yres;
}
#endif /*HAVE_EXIF*/

static int
read_exif( IMAGE *im, void *data, int data_length )
{
	char *data_copy;

	/* Always attach a copy of the unparsed exif data.
	 */
	if( !(data_copy = im_malloc( NULL, data_length )) )
		return( -1 );
	memcpy( data_copy, data, data_length );
	if( im_meta_set_blob( im, IM_META_EXIF_NAME, 
		(im_callback_fn) im_free, data_copy, data_length ) ) {
		im_free( data_copy );
		return( -1 );
	}

#ifdef HAVE_EXIF
{
	ExifData *ed;

	if( !(ed = exif_data_new_from_data( data, data_length )) )
		return( -1 );

	if( ed->size > 0 ) {
#ifdef DEBUG_VERBOSE
		show_tags( ed );
		show_values( ed );
#endif /*DEBUG_VERBOSE*/

		/* Attach informational fields for what we find.

		FIXME ... better to have this in the UI layer?

		Or we could attach non-human-readable tags here (int, double
		etc) and then move the human stuff to the UI layer?

		 */
		exif_data_foreach_content( ed, 
			(ExifDataForeachContentFunc) attach_exif_content, im );

		/* Look for resolution fields and use them to set the VIPS 
		 * xres/yres fields.
		 */
		set_vips_resolution( im, ed );
	}

	exif_data_free( ed );
}
#endif /*HAVE_EXIF*/

	return( 0 );
}

/* Number of app2 sections we can capture. Each one can be 64k, so 640k should
 * be enough for anyone (haha).
 */
#define MAX_APP2_SECTIONS (10)

/* Read a cinfo to a VIPS image. Set invert_pels if the pixel reader needs to
 * do 255-pel.
 */
static int
read_jpeg_header( struct jpeg_decompress_struct *cinfo, 
	IMAGE *out, gboolean *invert_pels, int shrink )
{
	jpeg_saved_marker_ptr p;
	int type;

	/* Capture app2 sections here for assembly.
	 */
	void *app2_data[MAX_APP2_SECTIONS] = { 0 };
	int app2_data_length[MAX_APP2_SECTIONS] = { 0 };
	int data_length;
	int i;

	/* Read JPEG header. libjpeg will set out_color_space sanely for us 
	 * for YUV YCCK etc.
	 */
	jpeg_read_header( cinfo, TRUE );
	cinfo->scale_denom = shrink;
	jpeg_calc_output_dimensions( cinfo );
	*invert_pels = FALSE;
	switch( cinfo->out_color_space ) {
	case JCS_GRAYSCALE:
		type = IM_TYPE_B_W;
		break;

	case JCS_CMYK:
		type = IM_TYPE_CMYK;
		/* Photoshop writes CMYK JPEG inverted :-( Maybe this is a
		 * way to spot photoshop CMYK JPGs.
		 */
		if( cinfo->saw_Adobe_marker ) 
			*invert_pels = TRUE;
		break;

	case JCS_RGB:
	default:
		type = IM_TYPE_sRGB;
		break;
	}

	/* Set VIPS header.
	 */
	im_initdesc( out,
		 cinfo->output_width, cinfo->output_height,
		 cinfo->output_components,
		 IM_BBITS_BYTE, IM_BANDFMT_UCHAR, IM_CODING_NONE, type,
		 1.0, 1.0, 0, 0 );

	/* Look for EXIF and ICC profile.
	 */
	for( p = cinfo->marker_list; p; p = p->next ) {
		switch( p->marker ) {
		case JPEG_APP0 + 1:
			/* EXIF data.
			 */
#ifdef DEBUG
			printf( "read_jpeg_header: seen %d bytes of EXIF\n",
				p->data_length );
#endif /*DEBUG*/
			if( read_exif( out, p->data, p->data_length ) )
				return( -1 );
			break;

		case JPEG_APP0 + 2:
			/* ICC profile.
			 */
#ifdef DEBUG
			printf( "read_jpeg_header: seen %d bytes of ICC\n",
				p->data_length );
#endif /*DEBUG*/

			if( p->data_length > 14 &&
				im_isprefix( "ICC_PROFILE", 
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

		default:
#ifdef DEBUG
			printf( "read_jpeg_header: seen %d bytes of data\n",
				p->data_length );
#endif /*DEBUG*/
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
		printf( "read_jpeg_header: assembled %d byte ICC profile\n",
			data_length );
#endif /*DEBUG*/

		if( !(data = im_malloc( NULL, data_length )) ) 
			return( -1 );

		p = 0;
		for( i = 0; i < MAX_APP2_SECTIONS && app2_data[i]; i++ ) {
			memcpy( data + p, app2_data[i], app2_data_length[i] );
			p += app2_data_length[i];
		}

		if( im_meta_set_blob( out, IM_META_ICC_NAME, 
			(im_callback_fn) im_free, data, data_length ) ) {
			im_free( data );
			return( -1 );
		}
	}

	return( 0 );
}

/* Read a cinfo to a VIPS image.
 */
static int
read_jpeg_image( struct jpeg_decompress_struct *cinfo, IMAGE *out, 
	gboolean invert_pels )
{
	int x, y, sz;
	JSAMPROW row_pointer[1];

	/* Check VIPS.
	 */
	if( im_outcheck( out ) || im_setupout( out ) )
		return( -1 );

	/* Get size of output line and make a buffer.
	 */
	sz = cinfo->output_width * cinfo->output_components;
	row_pointer[0] = (JSAMPLE *) (*cinfo->mem->alloc_large) 
		( (j_common_ptr) cinfo, JPOOL_IMAGE, sz );

	/* Start up decompressor.
	 */
	jpeg_start_decompress( cinfo );

	/* Process image.
	 */
	for( y = 0; y < out->Ysize; y++ ) {
		if( jpeg_read_scanlines( cinfo, &row_pointer[0], 1 ) != 1 ) {
			im_error( "im_jpeg2vips", _( "truncated JPEG file" ) );
			return( -1 );
		}
		if( invert_pels ) {
			for( x = 0; x < sz; x++ )
				row_pointer[0][x] = 255 - row_pointer[0][x];
		}
		if( im_writeline( y, out, row_pointer[0] ) )
			return( -1 );
	}

	/* Stop decompressor.
	 */
	jpeg_finish_decompress( cinfo );

	return( 0 );
}

/* Read a JPEG file into a VIPS image.
 */
static int
jpeg2vips( const char *name, IMAGE *out, gboolean header_only )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;
	int shrink;
	struct jpeg_decompress_struct cinfo;
        ErrorManager eman;
	FILE *fp;
	int result;
	gboolean invert_pels;

	/* Parse the filename.
	 */
	im_filename_split( name, filename, mode );
	p = &mode[0];
	shrink = 1;
	if( (q = im_getnextoption( &p )) ) {
		shrink = atoi( q );

		if( shrink != 1 && shrink != 2 && 
			shrink != 4 && shrink != 8 ) {
			im_error( "im_jpeg2vips", 
				_( "bad shrink factor %d" ), shrink );
			return( -1 );
		}
	}

	/* Make jpeg compression object.
 	 */
        cinfo.err = jpeg_std_error( &eman.pub );
	eman.pub.error_exit = new_error_exit;
	eman.pub.output_message = new_output_message;
	eman.fp = NULL;
	if( setjmp( eman.jmp ) ) {
		/* Here for longjmp() from new_error_exit().
		 */
		jpeg_destroy_decompress( &cinfo );

		return( -1 );
	}
        jpeg_create_decompress( &cinfo );

	/* Make input.
	 */
#ifdef BINARY_OPEN
        if( !(fp = fopen( filename, "rb" )) ) {
#else /*BINARY_OPEN*/
        if( !(fp = fopen( filename, "r" )) ) {
#endif /*BINARY_OPEN*/
		jpeg_destroy_decompress( &cinfo );
                im_error( "im_jpeg2vips", 
			_( "unable to open \"%s\"" ), filename );

                return( -1 );
        }
	eman.fp = fp;
        jpeg_stdio_src( &cinfo, fp );

	/* Need to read in APP1 (EXIF metadata) and APP2 (ICC profile).
	 */
	jpeg_save_markers( &cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &cinfo, JPEG_APP0 + 2, 0xffff );

	/* Convert!
	 */
	result = read_jpeg_header( &cinfo, out, &invert_pels, shrink );
	if( !header_only && !result )
		result = read_jpeg_image( &cinfo, out, invert_pels );

	/* Close and tidy.
	 */
	fclose( fp );
	eman.fp = NULL;
	jpeg_destroy_decompress( &cinfo );

	if( eman.pub.num_warnings != 0 ) {
		im_warn( "im_jpeg2vips", _( "read gave %ld warnings" ), 
			eman.pub.num_warnings );
		im_warn( "im_jpeg2vips", "%s", im_error_buffer() );
	}

	return( result );
}

/* Read a JPEG file into a VIPS image.
 */
int
im_jpeg2vips( const char *name, IMAGE *out )
{
	return( jpeg2vips( name, out, FALSE ) );
}

static int
isjpeg( const char *filename )
{
	unsigned char buf[2];

	if( im__get_bytes( filename, buf, 2 ) )
		if( (int) buf[0] == 0xff && (int) buf[1] == 0xd8 )
			return( 1 );

	return( 0 );
}

static int
jpeg2vips_header( const char *name, IMAGE *out )
{
	return( jpeg2vips( name, out, TRUE ) );
}

static const char *jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

void
im__jpeg_register( void )
{
	im_format_register( 
		"jpeg",			/* internal name */
		N_( "JPEG" ),		/* i18n'd visible name */
		jpeg_suffs,		/* Allowed suffixes */
		isjpeg,			/* is_a */
		jpeg2vips_header,	/* Load header only */
		im_jpeg2vips,		/* Load */
		im_vips2jpeg,		/* Save */
		NULL			/* Flags */
	);
}

#endif /*HAVE_JPEG*/
