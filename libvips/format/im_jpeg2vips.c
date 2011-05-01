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
#define DEBUG_VERBOSE
#define DEBUG
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
	im_error( "im_jpeg2vips", "%s",
		_( "JPEG support disabled" ) );

	return( -1 );
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
#include <vips/buf.h>
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
	im_error( "im_jpeg2vips", _( "%s" ), buffer );

#ifdef DEBUG
	printf( "im_jpeg2vips: new_output_message: \"%s\"\n", buffer );
#endif /*DEBUG*/
}

/* New error_exit handler.
 */
METHODDEF(void)
new_error_exit( j_common_ptr cinfo )
{
	ErrorManager *eman = (ErrorManager *) cinfo->err;

#ifdef DEBUG
	printf( "im_jpeg2vips: new_error_exit\n" );
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
	VipsBuf name;
	char value_text[256];
	VipsBuf value;
	char exif_value[256];

	vips_buf_init_static( &name, name_text, 256 );
	vips_buf_init_static( &value, value_text, 256 );

	vips_buf_appendf( &name, "exif-%s", exif_tag_get_title( entry->tag ) );
	vips_buf_appendf( &value, "%s (%s, %d bytes)", 
		exif_entry_get_value( entry, exif_value, 256 ),
		exif_format_get_name( entry->format ),
		entry->size );

	/* Can't do anything sensible with the error return.
	 */
	(void) im_meta_set_string( im, 
		vips_buf_all( &name ), vips_buf_all( &value ) );
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
		im_warn( "im_jpeg2vips", 
			"%s", _( "error reading resolution" ) );
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
		im_warn( "im_jpeg2vips", "%s", _( "bad resolution unit" ) );
		return;
	}

	im->Xres = xres;
	im->Yres = yres;
}

static int
attach_thumbnail( IMAGE *im, ExifData *ed )
{
	if( ed->size > 0 ) {
		char *thumb_copy;

		thumb_copy = im_malloc( NULL, ed->size );      
		memcpy( thumb_copy, ed->data, ed->size );

		if( im_meta_set_blob( im, "jpeg-thumbnail-data", 
			(im_callback_fn) im_free, thumb_copy, ed->size ) ) {
			im_free( thumb_copy );
			return( -1 );
		}
	}

	return( 0 );
}
#endif /*HAVE_EXIF*/

static int
read_exif( IMAGE *im, void *data, int data_length )
{
	char *data_copy;

	/* Horrifyingly, some JPEGs have several APP1 sections. We must only
	 * use the first one that starts "Exif.."
	 */
	if( ((char *) data)[0] != 'E' ||
		((char *) data)[1] != 'x' ||
		((char *) data)[2] != 'i' ||
		((char *) data)[3] != 'f' )
		return( 0 );
	if( im_header_get_typeof( im, IM_META_EXIF_NAME ) ) 
		return( 0 );

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

			Or we could attach non-human-readable tags here (int, 
			double etc) and then move the human stuff to the UI 
			layer?

		 */
		exif_data_foreach_content( ed, 
			(ExifDataForeachContentFunc) attach_exif_content, im );

		/* Look for resolution fields and use them to set the VIPS 
		 * xres/yres fields.
		 */
		set_vips_resolution( im, ed );

		attach_thumbnail( im, ed );
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
	cinfo->scale_num = 1;
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

	/* Interlaced jpegs need lots of memory to read, so our caller needs
	 * to know.
	 */
	(void) im_meta_set_int( out, "jpeg-multiscan", 
		jpeg_has_multiple_scans( cinfo ) );

	/* Look for EXIF and ICC profile.
	 */
	for( p = cinfo->marker_list; p; p = p->next ) {
		switch( p->marker ) {
		case JPEG_APP0 + 1:
			/* EXIF data.
			 */
#ifdef DEBUG
			printf( "read_jpeg_header: seen %d bytes of APP1\n",
				p->data_length );
#endif /*DEBUG*/
			if( read_exif( out, p->data, p->data_length ) )
				return( -1 );
			break;

		case JPEG_APP0 + 2:
			/* ICC profile.
			 */
#ifdef DEBUG
			printf( "read_jpeg_header: seen %d bytes of APP2\n",
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
		/* We set an error handler that longjmps() out, so I don't
		 * think this can fail.
		 */
		jpeg_read_scanlines( cinfo, &row_pointer[0], 1 );

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
	gboolean fail_on_warn;

	/* By default, we ignore any warnings. We want to get as much of
	 * the user's data as we can.
	 */
	fail_on_warn = FALSE;

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
	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "fail", q ) ) 
			fail_on_warn = TRUE;
	}

	/* Make jpeg dcompression object.
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
        if( !(fp = im__file_open_read( filename, NULL, FALSE )) ) 
                return( -1 );
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
		if( fail_on_warn ) {
			im_error( "im_jpeg2vips", "%s", im_error_buffer() );
			result = -1;
		}
		else {
			im_warn( "im_jpeg2vips", _( "read gave %ld warnings" ), 
				eman.pub.num_warnings );
			im_warn( "im_jpeg2vips", "%s", im_error_buffer() );
		}
	}

	return( result );
}

/**
 * im_jpeg2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a JPEG file into a VIPS image. It can read most 8-bit JPEG images, 
 * including CMYK and YCbCr.
 *
 * You can embed options in the filename. They have the form:
 *
 * |[
 * filename.jpg:<emphasis>shrink-factor</emphasis>,<emphasis>fail</emphasis>
 * ]|
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * <emphasis>shrink-factor</emphasis> 
 * Shrink by this integer factor during load.  Allowed values are 1, 2, 4
 * and 8. Shrinking during read is very much faster than decompressing the 
 * whole image and then shrinking. 
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>fail</emphasis> 
 * This makes the JPEG reader fail on any warnings. This can be useful for 
 * detecting truncated files, for example. Normally reading these produces 
 * a warning, but no fatal error.  
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Example:
 *
 * |[
 * im_jpeg2vips( "fred.jpg:8" out );
 * im_jpeg2vips( "fred.jpg:,fail" out );
 * ]|
 *
 * The first example will shrink by a factor of 8 during load. The second will
 * fail with an error if there are any problems loading the file.
 *
 * Any embedded ICC profiles are ignored: you always just get the RGB from 
 * the file. Instead, the embedded profile will be attached to the image as 
 * metadata.  You need to use something like im_icc_import() to get CIE 
 * values from the file. Any EXIF data is also attached as VIPS metadata.
 *
 * The int metadata item "jpeg-multiscan" is set to the result of 
 * jpeg_has_multiple_scans(). Interlaced jpeg images need a large amount of
 * memory to load, so this field gives callers a chance to handle these
 * images differently.
 *
 * The EXIF thumbnail, if present, is attached to the image as 
 * "jpeg-thumbnail-data". See im_meta_get_blob().
 *
 * See also: #VipsFormat, im_vips2jpeg().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_jpeg2vips( const char *filename, IMAGE *out )
{
	return( jpeg2vips( filename, out, FALSE ) );
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
  InputBuffer *src = (InputBuffer *) cinfo->src;
  size_t nbytes;

  if (src->start_of_file) {
    nbytes = src->len;
  }
  else {
    WARNMS(cinfo, JWRN_JPEG_EOF);
    /* Insert a fake EOI marker */
    src->buf[0] = (JOCTET) 0xFF;
    src->buf[1] = (JOCTET) JPEG_EOI;
    nbytes = 2;
  }

  src->pub.next_input_byte = src->buf;
  src->pub.bytes_in_buffer = nbytes;
  src->start_of_file = FALSE;

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
buf_source (j_decompress_ptr cinfo, void *buf, size_t len)
{
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

/**
 * im_bufjpeg2vips:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @header_only: set to just read the header
 *
 * Read a JPEG-formatted memory block into a VIPS image. It can read most 
 * 8-bit JPEG images, including CMYK and YCbCr.
 *
 * This function is handy for processing JPEG image thumbnails.
 *
 * See also: #VipsFormat, im_jpeg2vips().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_bufjpeg2vips( void *buf, size_t len, IMAGE *out, gboolean header_only )
{
	struct jpeg_decompress_struct cinfo;
        ErrorManager eman;
	int result;
	gboolean invert_pels;

	/* Make jpeg dcompression object.
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
	buf_source( &cinfo, buf, len );

	/* Need to read in APP1 (EXIF metadata) and APP2 (ICC profile).
	 */
	jpeg_save_markers( &cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &cinfo, JPEG_APP0 + 2, 0xffff );

	/* Convert!
	 */
	result = read_jpeg_header( &cinfo, out, &invert_pels, 1 );
	if( !header_only && !result )
		result = read_jpeg_image( &cinfo, out, invert_pels );

	/* Close and tidy.
	 */
	jpeg_destroy_decompress( &cinfo );

	return( result );
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

/* jpeg format adds no new members.
 */
typedef VipsFormat VipsFormatJpeg;
typedef VipsFormatClass VipsFormatJpegClass;

static void
vips_format_jpeg_class_init( VipsFormatJpegClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "jpeg";
	object_class->description = _( "JPEG" );

	format_class->is_a = isjpeg;
	format_class->header = jpeg2vips_header;
	format_class->load = im_jpeg2vips;
	format_class->save = im_vips2jpeg;
	format_class->suffs = jpeg_suffs;
}

static void
vips_format_jpeg_init( VipsFormatJpeg *object )
{
}

G_DEFINE_TYPE( VipsFormatJpeg, vips_format_jpeg, VIPS_TYPE_FORMAT );

#endif /*HAVE_JPEG*/
