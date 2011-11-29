/* load jpeg from a file
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
 * 	- redo as a class
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

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#include "jpeg.h"

typedef struct _VipsForeignLoadJpeg {
	VipsForeignLoad parent_object;

	/* Shrink by this much during load.
	 */
	int shrink;

	/* Fail on first warning.
	 */
	gboolean fail;

	/* For some jpeg CMYK formats we have to invert pels on read.
	 */
	gboolean invert_pels;

} VipsForeignLoadJpeg;

typedef VipsForeignLoadClass VipsForeignLoadJpegClass;

G_DEFINE_TYPE( VipsForeignLoadJpeg, vips_foreign_load_jpeg, VIPS_TYPE_FOREIGN_LOAD );

static int
vips_foreign_load_jpeg_build( VipsObject *object )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) object;

	if( jpeg->shrink != 1 && 
		jpeg->shrink != 2 && 
		jpeg->shrink != 4 && 
		jpeg->shrink != 8 ) {
		vips_error( "VipsFormatLoadJpeg", 
			_( "bad shrink factor %d" ), jpeg->shrink );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_jpeg_is_a( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) )
		if( (int) buf[0] == 0xff && (int) buf[1] == 0xd8 )
			return( TRUE );

	return( FALSE );
}

/* Read a cinfo to a VIPS image. Set invert_pels if the pixel reader needs to
 * do 255-pel.
 */
static int
vips_foreign_load_jpeg_read_header( VipsForeignLoadJpeg *jpeg, 
	struct jpeg_decompress_struct *cinfo, VipsImage *out )
{
	int type;

	/* Read JPEG header. libjpeg will set out_color_space sanely for us 
	 * for YUV YCCK etc.
	 */
	jpeg_read_header( cinfo, TRUE );
	cinfo->scale_denom = jpeg->shrink;
	cinfo->scale_num = 1;
	jpeg_calc_output_dimensions( cinfo );

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
			jpeg->invert_pels = TRUE;
		break;

	case JCS_RGB:
	default:
		type = IM_TYPE_sRGB;
		break;
	}

	/* Set VIPS header.
	 */
	vips_image_init_fields( out,
		 cinfo->output_width, cinfo->output_height,
		 cinfo->output_components,
		 VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, type,
		 1.0, 1.0 );

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
vips_exif_get_double( ExifData *ed, 
	ExifEntry *entry, unsigned long component, double *out )
{
	ExifByteOrder bo = exif_data_get_byte_order( ed );
	size_t sizeof_component = entry->size / entry->components;
	size_t offset = component * sizeof_component;

	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifRational value;

		value = exif_get_rational( entry->data + offset, bo );
		*out = (double) value.numerator / value.denominator;
	}
	else if( entry->format == EXIF_FORMAT_SRATIONAL ) {
		ExifSRational value;

		value = exif_get_srational( entry->data + offset, bo );
		*out = (double) value.numerator / value.denominator;
	}
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
	double dv;
	char txt[256];

	if( entry->format == EXIF_FORMAT_ASCII ) 
		vips_buf_appendf( buf, "%s ", entry->data );

	else if( entry->components < 10 &&
		!vips_exif_get_int( ed, entry, 0, &iv ) ) {
		for( i = 0; i < entry->components; i++ ) {
			vips_exif_get_int( ed, entry, i, &iv );
			vips_buf_appendf( buf, "%d ", iv );
		}
	}
	else if( entry->components < 10 &&
		!vips_exif_get_double( ed, entry, 0, &dv ) ) {
		for( i = 0; i < entry->components; i++ ) {
			vips_exif_get_double( ed, entry, i, &dv );
			/* Need to be locale independent.
			 */
			g_ascii_dtostr( txt, 256, dv );
			vips_buf_appendf( buf, "%s ", txt );
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

	vips_buf_appendf( &name, "exif-%s", exif_tag_get_title( entry->tag ) );
	vips_exif_to_s( ve->ed, entry, &value ); 

	/* Can't do anything sensible with the error return.
	 */
	(void) im_meta_set_string( ve->image, 
		vips_buf_all( &name ), vips_buf_all( &value ) );
}

static void
attach_exif_content( ExifContent *content, VipsExif *ve )
{
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) attach_exif_entry, ve );
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

	if( !(entry = find_entry( ed, tag )) ||
		entry->format != EXIF_FORMAT_RATIONAL ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_double( ed, entry, 0, out ) );
}

static int
get_entry_short( ExifData *ed, ExifTag tag, int *out )
{
	ExifEntry *entry;

	if( !(entry = find_entry( ed, tag )) ||
		entry->format != EXIF_FORMAT_SHORT ||
		entry->components != 1 )
		return( -1 );

	return( vips_exif_get_int( ed, entry, 0, out ) );
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

	/* Only use the first one.
	 */
	if( im_header_get_typeof( im, IM_META_EXIF_NAME ) ) {
#ifdef DEBUG
		printf( "read_exif: second EXIF block, ignoring\n" );
#endif /*DEBUG*/

		return( 0 );
	}

#ifdef DEBUG
	printf( "read_exif: attaching %d bytes of exif\n", data_length );
#endif /*DEBUG*/

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
		VipsExif ve;

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
		set_vips_resolution( im, ed );

		attach_thumbnail( im, ed );
	}

	exif_data_free( ed );
}
#endif /*HAVE_EXIF*/

	return( 0 );
}

static int
read_xmp( IMAGE *im, void *data, int data_length )
{
	char *data_copy;

	/* XMP sections start "http". Only use the first one.
	 */
	if( im_header_get_typeof( im, VIPS_META_XMP_NAME ) ) {
#ifdef DEBUG
		printf( "read_xmp: second XMP block, ignoring\n" );
#endif /*DEBUG*/

		return( 0 );
	}

#ifdef DEBUG
	printf( "read_xmp: attaching %d bytes of XMP\n", data_length );
#endif /*DEBUG*/

	/* Always attach a copy of the unparsed exif data.
	 */
	if( !(data_copy = im_malloc( NULL, data_length )) )
		return( -1 );
	memcpy( data_copy, data, data_length );
	if( im_meta_set_blob( im, VIPS_META_XMP_NAME, 
		(im_callback_fn) im_free, data_copy, data_length ) ) {
		im_free( data_copy );
		return( -1 );
	}

	return( 0 );
}

/* Number of app2 sections we can capture. Each one can be 64k, so 6400k should
 * be enough for anyone (haha).
 */
#define MAX_APP2_SECTIONS (100)

static int
vips_foreign_load_jpeg_meta( VipsForeignLoadJpeg *jpeg, 
	struct jpeg_decompress_struct *cinfo, VipsImage *out )
{
	/* Capture app2 sections here for assembly.
	 */
	void *app2_data[MAX_APP2_SECTIONS] = { 0 };
	int app2_data_length[MAX_APP2_SECTIONS] = { 0 };
	int data_length;
	jpeg_saved_marker_ptr p;
	int i;

	/* Interlaced jpegs need lots of memory to read, so our caller needs
	 * to know.
	 */
	vips_image_set_int( out, "jpeg-multiscan", 
		jpeg_has_multiple_scans( cinfo ) );

	/* Look for EXIF and ICC profile.
	 */
	for( p = cinfo->marker_list; p; p = p->next ) {
#ifdef DEBUG
{
		printf( "vips_foreign_load_jpeg_read_header: "
			"seen %d bytes of APP%d\n",
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
				im_isprefix( "Exif", (char *) p->data ) &&
				read_exif( out, p->data, p->data_length ) )
				return( -1 );

			if( p->data_length > 4 &&
				im_isprefix( "http", (char *) p->data ) &&
				read_xmp( out, p->data, p->data_length ) )
				return( -1 );

			break;

		case JPEG_APP0 + 2:
			/* ICC profile.
			 */
			if( p->data_length > 14 &&
				im_isprefix( "ICC_PROFOREIGN", 
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
		int x;

#ifdef DEBUG
		printf( "vips_foreign_load_jpeg_read_header: "
			"assembled %d byte ICC profile\n",
			data_length );
#endif /*DEBUG*/

		data = g_malloc( data_length );
		x = 0;
		for( i = 0; i < MAX_APP2_SECTIONS && app2_data[i]; i++ ) {
			memcpy( data + x, app2_data[i], app2_data_length[i] );
			x += app2_data_length[i];
		}
		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) g_free, data, data_length );
	}

	return( 0 );
}

/* Read just the image header into ->out.
 */
static int
vips_foreign_load_jpeg_header( VipsForeignLoad *load )
{
	VipsForeign *file = VIPS_FOREIGN( load );
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;

	struct jpeg_decompress_struct cinfo;
        ErrorManager eman;
	FILE *fp;
	int result;

	/* Make jpeg dcompression object.
 	 */
        cinfo.err = jpeg_std_error( &eman.pub );
	eman.pub.error_exit = vips__new_error_exit;
	eman.pub.output_message = vips__new_output_message;
	eman.fp = NULL;
	if( setjmp( eman.jmp ) ) {
		/* Here for longjmp() from vips__new_error_exit().
		 */
		jpeg_destroy_decompress( &cinfo );

		return( -1 );
	}
        jpeg_create_decompress( &cinfo );

	/* Make input.
	 */
        if( !(fp = vips__file_open_read( file->filename, NULL, FALSE )) ) 
                return( -1 );
	eman.fp = fp;
        jpeg_stdio_src( &cinfo, fp );

	/* Need to read in APP1 (EXIF metadata) and APP2 (ICC profile).
	 */
	jpeg_save_markers( &cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &cinfo, JPEG_APP0 + 2, 0xffff );

	/* Convert!
	 */
	result = vips_foreign_load_jpeg_read_header( jpeg, &cinfo, load->out );

	/* Get extra metadata too.
	 */
	if( !result )
		result = vips_foreign_load_jpeg_meta( jpeg, &cinfo, load->out );

	/* Close and tidy.
	 */
	fclose( fp );
	eman.fp = NULL;
	jpeg_destroy_decompress( &cinfo );

	return( result );
}

/* Read a cinfo to a VIPS image.
 */
static int
vips_foreign_load_jpeg_read_image( VipsForeignLoadJpeg *jpeg,
	struct jpeg_decompress_struct *cinfo, VipsImage *out )
{
	int x, y, sz;
	JSAMPROW row_pointer[1];

	/* Check VIPS.
	 */
	if( vips_image_wio_output( out ) )
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

		if( jpeg->invert_pels ) {
			for( x = 0; x < sz; x++ )
				row_pointer[0][x] = 255 - row_pointer[0][x];
		}
		if( vips_image_write_line( out, y, row_pointer[0] ) )
			return( -1 );
	}

	/* Stop decompressor.
	 */
	jpeg_finish_decompress( cinfo );

	return( 0 );
}

static int
vips_foreign_load_jpeg_load( VipsForeignLoad *load )
{
	VipsForeign *file = VIPS_FOREIGN( load );
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;

	struct jpeg_decompress_struct cinfo;
        ErrorManager eman;
	FILE *fp;
	int result;

	/* Make jpeg dcompression object.
 	 */
        cinfo.err = jpeg_std_error( &eman.pub );
	eman.pub.error_exit = vips__new_error_exit;
	eman.pub.output_message = vips__new_output_message;
	eman.fp = NULL;
	if( setjmp( eman.jmp ) ) {
		/* Here for longjmp() from vips__new_error_exit().
		 */
		jpeg_destroy_decompress( &cinfo );

		return( -1 );
	}
        jpeg_create_decompress( &cinfo );

	/* Make input.
	 */
        if( !(fp = vips__file_open_read( file->filename, NULL, FALSE )) ) 
                return( -1 );
	eman.fp = fp;
        jpeg_stdio_src( &cinfo, fp );

	/* Convert!
	 */
	result = vips_foreign_load_jpeg_read_header( jpeg, &cinfo, load->real );
	if( !result )
		result = vips_foreign_load_jpeg_read_image( jpeg, 
			&cinfo, load->real );

	/* Close and tidy.
	 */
	fclose( fp );
	eman.fp = NULL;
	jpeg_destroy_decompress( &cinfo );

	if( eman.pub.num_warnings != 0 ) {
		if( jpeg->fail ) {
			vips_error( "VipsForeignLoadJpeg", 
				"%s", vips_error_buffer() );
			result = -1;
		}
		else {
			vips_warn( "VipsForeignLoadJpeg", 
				_( "read gave %ld warnings" ), 
				eman.pub.num_warnings );
			vips_warn( "VipsForeignLoadJpeg", 
				"%s", vips_error_buffer() );
		}
	}

	return( result );
}

static const char *jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

static void
vips_foreign_load_jpeg_class_init( VipsForeignLoadJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *file_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload";
	object_class->description = _( "load jpeg from file" );
	object_class->build = vips_foreign_load_jpeg_build;

	file_class->suffs = jpeg_suffs;

	load_class->is_a = vips_foreign_load_jpeg_is_a;
	load_class->header = vips_foreign_load_jpeg_header;
	load_class->load = vips_foreign_load_jpeg_load;

	VIPS_ARG_INT( class, "shrink", 10, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJpeg, shrink ),
		1, 16, 1 );

	VIPS_ARG_BOOL( class, "fail", 11, 
		_( "Fail" ), 
		_( "Fail on first warning" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJpeg, fail ),
		FALSE );
}

static void
vips_foreign_load_jpeg_init( VipsForeignLoadJpeg *jpeg )
{
	jpeg->shrink = 1;
}

