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
 * 9/9/14
 * 	- support "none" as a resolution unit
 * 16/10/14
 * 	- add "autorotate" option
 * 20/1/15
 * 	- don't call jpeg_finish_decompress(), all it does is read and check 
 * 	  the tail of the file
 * 26/2/15
 * 	- close the jpeg read down early for a header read ... this saves an
 * 	  fd during jpg read, handy for large numbers of input images 
 * 15/7/15
 * 	- save exif tags using @name, not @title ... @title is subject to i18n
 * 21/2/16
 * 	- _destroy the decompress object as soon as we can, frees loads of
 * 	  memory for progressive jpg files
 * 26/5/16
 * 	- switch to new orientation tag
 * 11/7/16
 * 	- new --fail handling
 * 07/09/16
 *      - don't use the exif resolution if x_resolution / y_resolution /
 *        resolution_unit is missing
 * 7/11/16
 * 	- exif handling moved out to exif.c
 * 4/1/17
 * 	- don't warn for missing exif res, since we fall back to jfif now
 * 17/1/17
 * 	- invalidate operation on read error
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

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#include "jpeg.h"

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

	/* Track the y pos during a read with this.
	 */
	int y_pos;

	/* Use orientation tag to automatically rotate and flip image
	 * during load.
	 */
	gboolean autorotate;
} ReadJpeg;

/* This can be called many times.
 */
static int
readjpeg_free( ReadJpeg *jpeg )
{
	int result;

	result = 0;

	if( jpeg->eman.pub.num_warnings != 0 ) {
		g_warning( _( "read gave %ld warnings" ), 
			jpeg->eman.pub.num_warnings );
		g_warning( "%s", vips_error_buffer() );

		/* Make the message only appear once.
		 */
		jpeg->eman.pub.num_warnings = 0;
	}

	/* Don't call jpeg_finish_decompress(). It just checks the tail of the
	 * file and who cares about that. All mem is freed in
	 * jpeg_destroy_decompress().
	 */

	VIPS_FREEF( fclose, jpeg->eman.fp );
	VIPS_FREE( jpeg->filename );
	jpeg->eman.fp = NULL;

	/* I don't think this can fail. It's harmless to call many times. 
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
readjpeg_new( VipsImage *out, 
	int shrink, gboolean fail, gboolean readbehind, gboolean autorotate )
{
	ReadJpeg *jpeg;

	if( !(jpeg = VIPS_NEW( out, ReadJpeg )) )
		return( NULL );

	jpeg->out = out;
	jpeg->shrink = shrink;
	jpeg->fail = fail;
	jpeg->readbehind = readbehind;
	jpeg->filename = NULL;
        jpeg->cinfo.err = jpeg_std_error( &jpeg->eman.pub );
	jpeg->eman.pub.error_exit = vips__new_error_exit;
	jpeg->eman.pub.output_message = vips__new_output_message;
	jpeg->eman.fp = NULL;
	jpeg->y_pos = 0;
	jpeg->autorotate = autorotate;

	/* This is used by the error handlers to signal invalidate on the
	 * output image.
	 */
        jpeg->cinfo.client_data = out;

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
		case 0:
			/* None. Just set.
			 */
			xres = cinfo->X_density;
			yres = cinfo->Y_density;
			break;

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
			g_warning( "%s", _( "unknown JFIF resolution unit" ) );
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
				vips_isprefix( "Exif", (char *) p->data ) &&
				attach_blob( out, VIPS_META_EXIF_NAME, 
					p->data, p->data_length ) )
				return( -1 );

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
#ifdef DEBUG
			printf( "read_jpeg_header: "
				"ignoring %d byte APP%d block\n", 
				p->data_length, p->marker - JPEG_APP0 );
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

	if( vips__exif_parse( out ) )
		return( -1 );

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
	printf( "read_jpeg_generate: %p line %d, %d rows\n", 
		g_thread_self(), r->top, r->height );
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
	if( r->top != jpeg->y_pos ) {
		VIPS_GATE_STOP( "read_jpeg_generate: work" );
		vips_error( "VipsJpeg", 
			_( "out of order read at line %d" ), jpeg->y_pos );

		return( -1 );
	}

	/* Here for longjmp() from vips__new_error_exit().
	 */
	if( setjmp( jpeg->eman.jmp ) ) {
		VIPS_GATE_STOP( "read_jpeg_generate: work" );

		return( -1 );
	}

	/* If --fail is set, we make read fail on any warnings. This will stop
	 * on any errors from the previous jpeg_read_scanlines().
	 */
	if( jpeg->eman.pub.num_warnings > 0 &&
		jpeg->fail ) {
		VIPS_GATE_STOP( "read_jpeg_generate: work" );

		/* Only fail once.
		 */
		jpeg->eman.pub.num_warnings = 0;

		*stop = TRUE;

		return( -1 );
	}

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

	/* Progressive images can have a lot of memory in the decompress
	 * object, destroy as soon as we can. Safe to call many times. 
	 */
	if( jpeg->y_pos >= or->im->Ysize ) 
		jpeg_destroy_decompress( &jpeg->cinfo );

	VIPS_GATE_STOP( "read_jpeg_generate: work" );

	return( 0 );
}

/* Auto-rotate, if rotate_image is set.
 */
static VipsImage *
read_jpeg_rotate( VipsObject *process, VipsImage *im )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 2 );
	VipsAngle angle = vips_autorot_get_angle( im );

	if( angle != VIPS_ANGLE_D0 ) {
		/* Need to copy to memory or disc, we have to stay seq.
		 */
		const guint64 image_size = VIPS_IMAGE_SIZEOF_IMAGE( im );
		const guint64 disc_threshold = vips_get_disc_threshold();

		if( image_size > disc_threshold ) 
			t[0] = vips_image_new_temp_file( "%s.v" );
		else
			t[0] = vips_image_new_memory();

		if( vips_image_write( im, t[0] ) ||
			vips_rot( t[0], &t[1], angle, NULL ) )
			return( NULL );
		im = t[1];

		vips_autorot_remove_angle( im ); 
	}

	return( im );
}

/* Read a cinfo to a VIPS image.
 */
static int
read_jpeg_image( ReadJpeg *jpeg, VipsImage *out )
{
	struct jpeg_decompress_struct *cinfo = &jpeg->cinfo;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	VipsImage *im;

	/* Here for longjmp() from vips__new_error_exit().
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	t[0] = vips_image_new();
	if( read_jpeg_header( jpeg, t[0] ) )
		return( -1 );

	jpeg_start_decompress( cinfo );

#ifdef DEBUG
	printf( "read_jpeg_image: starting decompress\n" );
#endif /*DEBUG*/

	if( vips_image_generate( t[0], 
		NULL, read_jpeg_generate, NULL, 
		jpeg, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", 8,
			NULL ) )
		return( -1 );

	im = t[1];
	if( jpeg->autorotate )
		im = read_jpeg_rotate( VIPS_OBJECT( out ), im );

	if( vips_image_write( im, out ) )
		return( -1 );

	return( 0 );
}

/* Read the jpeg from file or buffer.
 */
static int
vips__jpeg_read( ReadJpeg *jpeg, VipsImage *out, gboolean header_only )
{
	/* Need to read in APP1 (EXIF metadata), APP2 (ICC profile), APP13
	 * (photoshop IPCT).
	 */
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 1, 0xffff );
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 2, 0xffff );
	jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + 13, 0xffff );

#ifdef DEBUG
{
	int i;

	/* Handy for debugging ... spot any extra  markers.
	 */
	for( i = 0; i < 16; i++ ) 
		jpeg_save_markers( &jpeg->cinfo, JPEG_APP0 + i, 0xffff );
}
#endif /*DEBUG*/

	/* Convert!
	 */
	if( header_only ) {
		if( read_jpeg_header( jpeg, out ) )
			return( -1 ); 

		/* Swap width and height if we're going to rotate this image.
		 */
		if( jpeg->autorotate ) { 
			VipsAngle angle = vips_autorot_get_angle( out ); 

			if( angle == VIPS_ANGLE_D90 || 
				angle == VIPS_ANGLE_D270 )
				VIPS_SWAP( int, out->Xsize, out->Ysize );

			/* We won't be returning an orientation tag.
			 */
			vips_autorot_remove_angle( out ); 
		}
	}
	else {
		if( read_jpeg_image( jpeg, out ) )
			return( -1 );
	}

	return( 0 );
}

/* Read a JPEG file into a VIPS image.
 */
int
vips__jpeg_read_file( const char *filename, VipsImage *out, 
	gboolean header_only, int shrink, gboolean fail, gboolean readbehind,
	gboolean autorotate )
{
	ReadJpeg *jpeg;

	if( !(jpeg = readjpeg_new( out, 
		shrink, fail, readbehind, autorotate )) )
		return( -1 );

	/* Here for longjmp() from vips__new_error_exit() during startup.
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	/* Set input to file.
	 */
	if( readjpeg_file( jpeg, filename ) ) 
		return( -1 );

	if( vips__jpeg_read( jpeg, out, header_only ) ) 
		return( -1 );

	VIPS_SETSTR( out->filename, filename );

	/* We can kill off the decompress early if this is just a header read.
	 * This saves an fd during read.
	 */
	if( header_only )
		readjpeg_free( jpeg );

	return( 0 );
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
	const JOCTET *buf;
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
    src->start_of_file = FALSE;
  }
  else {
    WARNMS(cinfo, JWRN_JPEG_EOF);
    src->pub.next_input_byte = eoi_buffer;
    src->pub.bytes_in_buffer = 2;
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
readjpeg_buffer (ReadJpeg *jpeg, const void *buf, size_t len)
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
vips__jpeg_read_buffer( const void *buf, size_t len, VipsImage *out, 
	gboolean header_only, int shrink, int fail, gboolean readbehind, 
	gboolean autorotate )
{
	ReadJpeg *jpeg;

	if( !(jpeg = readjpeg_new( out, 
		shrink, fail, readbehind, autorotate )) )
		return( -1 );

	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	/* Set input to buffer.
	 */
	readjpeg_buffer( jpeg, buf, len );

	if( vips__jpeg_read( jpeg, out, header_only ) ) 
		return( -1 );

	return( 0 );
}

int
vips__isjpeg_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

	if( len >= 2 &&
		str[0] == 0xff && 
		str[1] == 0xd8 )
		return( 1 );

	return( 0 );
}

int
vips__isjpeg( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) &&
		vips__isjpeg_buffer( buf, 2 ) )
		return( 1 );

	return( 0 );
}

#endif /*HAVE_JPEG*/
