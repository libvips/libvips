/* wrap jpeg libray for write
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
 * 20/4/06
 * 	- auto convert to sRGB/mono for save
 * 13/10/06
 * 	- add </libexif/ prefix if required
 * 19/1/07
 * 	- oop, libexif confusion
 * 2/11/07
 * 	- use im_wbuffer() API for BG writes
 * 15/2/08
 * 	- write CMYK if Bands == 4 and Type == CMYK
 * 12/5/09
 *	- fix signed/unsigned warning
 * 13/8/09
 * 	- allow "none" for profile, meaning don't embed one
 * 4/2/10
 * 	- gtkdoc
 * 17/7/10
 * 	- use g_assert()
 * 	- allow space for the header in init_destination(), helps writing very
 * 	  small JPEGs (thanks Tim Elliott)
 * 18/7/10
 * 	- collect im_vips2bufjpeg() output in a list of blocks ... we no
 * 	  longer overallocate or underallocate
 * 8/7/11
 * 	- oop CMYK write was not inverting, thanks Ole
 * 12/10/2011
 * 	- write XMP data
 * 18/10/2011
 * 	- update Orientation as well
 * 3/11/11
 * 	- rebuild exif tags from coded metadata values 
 * 24/11/11
 * 	- turn into a set of write fns ready to be called from a class
 * 7/8/12
 * 	- use VIPS_META_RESOLUTION_UNIT to select resolution unit
 * 16/11/12
 * 	- read ifds from exif fields 
 * 	- optionally parse rationals as a/b
 * 	- update exif image dimensions
 * 21/11/12
 * 	- attach IPCT data (app13), thanks Gary
 * 2/10/13 Lovell Fuller
 * 	- add optimize_coding parameter
 * 	- add progressive mode
 * 12/11/13
 * 	- add "strip" option to remove all metadata
 * 13/11/13
 * 	- add a "no_subsample" option to disable chroma subsample
 * 9/9/14
 * 	- support "none" as a resolution unit
 * 8/7/15
 * 	- omit oversized jpeg markers
 * 15/7/15
 * 	- exif tags use @name, not @title
 * 	- set arbitrary exif tags from metadata
 * 25/11/15	
 * 	- don't write JFIF headers if we are stripping, thanks Benjamin
 * 13/4/16
 * 	- remove deleted exif fields more carefully
 * 9/5/16 felixbuenemann
 * 	- add quant_table
 * 26/5/16
 * 	- switch to new orientation tag
 * 9/7/16
 * 	- turn off chroma subsample for Q > 90
 * 7/11/16
 * 	- move exif handling out to exif.c
 * 27/2/17
 * 	- use dbuf for memory output
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

#ifdef HAVE_JPEG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "pforeign.h"

#include "jpeg.h"

/* New output message method - send to VIPS.
 */
void
vips__new_output_message( j_common_ptr cinfo )
{
	char buffer[JMSG_LENGTH_MAX];

	(*cinfo->err->format_message)( cinfo, buffer );
	vips_error( "VipsJpeg", _( "%s" ), buffer );

#ifdef DEBUG
	printf( "vips__new_output_message: \"%s\"\n", buffer );
#endif /*DEBUG*/

	/* This is run for things like file truncated. Signal invalidate to
	 * force this op out of cache. 
	 */
        if( cinfo->client_data )
		vips_foreign_load_invalidate( VIPS_IMAGE( cinfo->client_data ) );
}

/* New error_exit handler.
 */
void
vips__new_error_exit( j_common_ptr cinfo )
{
	ErrorManager *eman = (ErrorManager *) cinfo->err;

#ifdef DEBUG
	printf( "vips__new_error_exit:\n" );
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

/* What we track during a JPEG write.
 */
typedef struct {
	VipsImage *in;
	struct jpeg_compress_struct cinfo;
        ErrorManager eman;
	JSAMPROW *row_pointer;
	char *profile_bytes;
	size_t profile_length;
	VipsImage *inverted;
} Write;

static void
write_destroy( Write *write )
{
	jpeg_destroy_compress( &write->cinfo );
	VIPS_FREEF( fclose, write->eman.fp );
	VIPS_FREE( write->row_pointer );
	VIPS_FREE( write->profile_bytes );
	VIPS_UNREF( write->inverted );

	g_free( write );
}

static Write *
write_new( VipsImage *in )
{
	Write *write;

	if( !(write = g_new0( Write, 1 )) )
		return( NULL );

	write->in = in;
	write->row_pointer = NULL;
        write->cinfo.err = jpeg_std_error( &write->eman.pub );
	write->eman.pub.error_exit = vips__new_error_exit;
	write->eman.pub.output_message = vips__new_output_message;
	write->eman.fp = NULL;
	write->profile_bytes = NULL;
	write->profile_length = 0;
	write->inverted = NULL;

        return( write );
}

static int
write_blob( Write *write, const char *field, int app )
{
	unsigned char *data;
	size_t data_length;

	if( vips_image_get_typeof( write->in, field ) ) {
		if( vips_image_get_blob( write->in, field, 
			(void *) &data, &data_length ) )
			return( -1 );

		/* Single jpeg markers can only hold 64kb, large objects must
		 * be split into multiple markers.
		 *
		 * Unfortunately, how this splitting is done depends on the
		 * data type. For example, ICC and XMP have completely 
		 * different ways of doing this.
		 *
		 * For now, just ignore oversize objects and warn.
		 */
		if( data_length > 65530 ) 
			g_warning( _( "field \"%s\" is too large "
				"for a single JPEG marker, ignoring" ), 
				field );
		else {
#ifdef DEBUG
			printf( "write_blob: attaching %zd bytes of %s\n", 
				data_length, field );
#endif /*DEBUG*/

			jpeg_write_marker( &write->cinfo, app, 
				data, data_length ); } }

	return( 0 );
}

static int
write_exif( Write *write )
{
	if( vips__exif_update( write->in ) ||
		write_blob( write, VIPS_META_EXIF_NAME, JPEG_APP0 + 1 ) )
		return( -1 );

	return( 0 );
}

/* ICC writer from lcms, slight tweaks.
 */

#define ICC_MARKER  (JPEG_APP0 + 2)     /* JPEG marker code for ICC */
#define ICC_OVERHEAD_LEN  14            /* size of non-profile data in APP2 */
#define MAX_BYTES_IN_MARKER  65533      /* maximum data len of a JPEG marker */
#define MAX_DATA_BYTES_IN_MARKER  (MAX_BYTES_IN_MARKER - ICC_OVERHEAD_LEN)

/*
 * This routine writes the given ICC profile data into a JPEG file.
 * It *must* be called AFTER calling jpeg_start_compress() and BEFORE
 * the first call to jpeg_write_scanlines().
 * (This ordering ensures that the APP2 marker(s) will appear after the
 * SOI and JFIF or Adobe markers, but before all else.)
 */

static void
write_profile_data (j_compress_ptr cinfo,
                   const JOCTET *icc_data_ptr,
                   unsigned int icc_data_len)
{
  unsigned int num_markers;     /* total number of markers we'll write */
  int cur_marker = 1;           /* per spec, counting starts at 1 */
  unsigned int length;          /* number of bytes to write in this marker */

  /* rounding up will fail for length == 0 */
  g_assert( icc_data_len > 0 );

  /* Calculate the number of markers we'll need, rounding up of course */
  num_markers = (icc_data_len + MAX_DATA_BYTES_IN_MARKER - 1) / 
	  MAX_DATA_BYTES_IN_MARKER;

  while (icc_data_len > 0) {
    /* length of profile to put in this marker */
    length = icc_data_len;
    if (length > MAX_DATA_BYTES_IN_MARKER)
      length = MAX_DATA_BYTES_IN_MARKER;
    icc_data_len -= length;

    /* Write the JPEG marker header (APP2 code and marker length) */
    jpeg_write_m_header(cinfo, ICC_MARKER,
                        (unsigned int) (length + ICC_OVERHEAD_LEN));

    /* Write the marker identifying string "ICC_PROFILE" (null-terminated).
     * We code it in this less-than-transparent way so that the code works
     * even if the local character set is not ASCII.
     */
    jpeg_write_m_byte(cinfo, 0x49);
    jpeg_write_m_byte(cinfo, 0x43);
    jpeg_write_m_byte(cinfo, 0x43);
    jpeg_write_m_byte(cinfo, 0x5F);
    jpeg_write_m_byte(cinfo, 0x50);
    jpeg_write_m_byte(cinfo, 0x52);
    jpeg_write_m_byte(cinfo, 0x4F);
    jpeg_write_m_byte(cinfo, 0x46);
    jpeg_write_m_byte(cinfo, 0x49);
    jpeg_write_m_byte(cinfo, 0x4C);
    jpeg_write_m_byte(cinfo, 0x45);
    jpeg_write_m_byte(cinfo, 0x0);

    /* Add the sequencing info */
    jpeg_write_m_byte(cinfo, cur_marker);
    jpeg_write_m_byte(cinfo, (int) num_markers);

    /* Add the profile data */
    while (length--) {
      jpeg_write_m_byte(cinfo, *icc_data_ptr);
      icc_data_ptr++;
    }
    cur_marker++;
  }
}

/* Write an ICC Profile from a file into the JPEG stream.
 */
static int
write_profile_file( Write *write, const char *profile )
{
	if( !(write->profile_bytes = 
		vips__file_read_name( profile, vips__icc_dir(), 
		&write->profile_length )) ) 
		return( -1 );
	write_profile_data( &write->cinfo, 
		(JOCTET *) write->profile_bytes, write->profile_length );

#ifdef DEBUG
	printf( "write_profile_file: attached profile \"%s\"\n", profile );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_profile_meta( Write *write )
{
	void *data;
	size_t data_length;

	if( vips_image_get_blob( write->in, VIPS_META_ICC_NAME, 
		&data, &data_length ) )
		return( -1 );

	write_profile_data( &write->cinfo, data, data_length );

#ifdef DEBUG
	printf( "write_profile_meta: attached %zd byte profile from header\n",
		data_length );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_jpeg_block( VipsRegion *region, VipsRect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	for( i = 0; i < area->height; i++ )
		write->row_pointer[i] = (JSAMPROW) 
			VIPS_REGION_ADDR( region, 0, area->top + i );

	/* Catch any longjmp()s from jpeg_write_scanlines() here.
	 */
	if( setjmp( write->eman.jmp ) ) 
		return( -1 );

	jpeg_write_scanlines( &write->cinfo, write->row_pointer, area->height );

	return( 0 );
}

/* Write a VIPS image to a JPEG compress struct.
 */
static int
write_vips( Write *write, int qfac, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip, 
	gboolean no_subsample, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans, int quant_table )
{
	VipsImage *in;
	J_COLOR_SPACE space;

	/* The image we'll be writing ... can change, see CMYK.
	 */
	in = write->in;

	/* Should have been converted for save.
	 */
        g_assert( in->BandFmt == VIPS_FORMAT_UCHAR );
	g_assert( in->Coding == VIPS_CODING_NONE );
        g_assert( in->Bands == 1 || 
		in->Bands == 3 || 
		in->Bands == 4 );

        /* Check input image.
         */
	if( vips_image_pio_input( in ) )
		return( -1 );

	/* Set compression parameters.
	 */
        write->cinfo.image_width = in->Xsize;
        write->cinfo.image_height = in->Ysize;
	write->cinfo.input_components = in->Bands;
	if( in->Bands == 4 && 
		in->Type == VIPS_INTERPRETATION_CMYK ) {
		space = JCS_CMYK;
		/* IJG always sets an Adobe marker, so we should invert CMYK.
		 */
		if( vips_invert( in, &write->inverted, NULL ) ) 
			return( -1 );
		in = write->inverted;
	}
	else if( in->Bands == 3 )
		space = JCS_RGB;
	else if( in->Bands == 1 )
		space = JCS_GRAYSCALE;
	else 
		/* Use luminance compression for all channels.
		 */
		space = JCS_UNKNOWN;
	write->cinfo.in_color_space = space; 

	/* Build VIPS output stuff now we know the image we'll be writing.
	 */
	if( !(write->row_pointer = VIPS_ARRAY( NULL, in->Ysize, JSAMPROW )) )
		return( -1 );

#ifdef HAVE_JPEG_EXT_PARAMS
	/* Reset compression profile to libjpeg defaults
	 */
	if( jpeg_c_int_param_supported( &write->cinfo, JINT_COMPRESS_PROFILE ) )
		jpeg_c_set_int_param( &write->cinfo, 
			JINT_COMPRESS_PROFILE, JCP_FASTEST );
#endif

	/* Reset to default.
	 */
        jpeg_set_defaults( &write->cinfo );

 	/* Compute optimal Huffman coding tables.
	 */
	write->cinfo.optimize_coding = optimize_coding;

#ifdef HAVE_JPEG_EXT_PARAMS
	/* Apply trellis quantisation to each 8x8 block. Implies 
	 * "optimize_coding".
	 */
	if( trellis_quant ) {
		if( jpeg_c_bool_param_supported( &write->cinfo, 
			JBOOLEAN_TRELLIS_QUANT ) ) {
			jpeg_c_set_bool_param( &write->cinfo,
				JBOOLEAN_TRELLIS_QUANT, TRUE );
			write->cinfo.optimize_coding = TRUE;
		}
		else 
			g_warning( "%s", _( "trellis_quant unsupported" ) );
	}

	/* Apply overshooting to samples with extreme values e.g. 0 & 255 
	 * for 8-bit.
	 */
	if( overshoot_deringing ) {
		if( jpeg_c_bool_param_supported( &write->cinfo, 
			JBOOLEAN_OVERSHOOT_DERINGING ) ) 
			jpeg_c_set_bool_param( &write->cinfo,
				JBOOLEAN_OVERSHOOT_DERINGING, TRUE );
		else 
			g_warning( "%s", 
				_( "overshoot_deringing unsupported" ) );
	}
	/* Split the spectrum of DCT coefficients into separate scans.
	 * Requires progressive output. Must be set before 
	 * jpeg_simple_progression.
	 */
	if( optimize_scans ) {
		if( progressive ) {
			if( jpeg_c_bool_param_supported( &write->cinfo, 
				JBOOLEAN_OPTIMIZE_SCANS ) ) 
				jpeg_c_set_bool_param( &write->cinfo, 
					JBOOLEAN_OPTIMIZE_SCANS, TRUE );
			else 
				g_warning( "%s", 
					_( "ignoring optimize_scans" ) );
		}
		else 
			g_warning( "%s", 
				_( "ignoring optimize_scans for baseline" ) );
	}

	/* Use predefined quantization table.
	 */
	if( quant_table > 0 ) {
		if( jpeg_c_int_param_supported( &write->cinfo,
			JINT_BASE_QUANT_TBL_IDX ) )
			jpeg_c_set_int_param( &write->cinfo,
				JINT_BASE_QUANT_TBL_IDX, quant_table );
		else
			g_warning( "%s", 
				_( "setting quant_table unsupported" ) );
	}
#else
	/* Using jpeglib.h without extension parameters, warn of ignored 
	 * options.
	 */
	if( trellis_quant ) 
		g_warning( "%s", _( "ignoring trellis_quant" ) );
	if( overshoot_deringing ) 
		g_warning( "%s", _( "ignoring overshoot_deringing" ) );
	if( optimize_scans ) 
		g_warning( "%s", _( "ignoring optimize_scans" ) );
	if( quant_table > 0 )
		g_warning( "%s", _( "ignoring quant_table" ) );
#endif

	/* Set compression quality. Must be called after setting params above.
	 */
        jpeg_set_quality( &write->cinfo, qfac, TRUE );

	/* Enable progressive write.
	 */
	if( progressive ) 
		jpeg_simple_progression( &write->cinfo ); 

	/* Turn off chroma subsampling. Follow IM and do it automatically for
	 * high Q. 
	 */
	if( no_subsample ||
		qfac > 90 ) { 
		int i;

		for( i = 0; i < in->Bands; i++ ) { 
			write->cinfo.comp_info[i].h_samp_factor = 1;
			write->cinfo.comp_info[i].v_samp_factor = 1;
		}
	}

	/* Don't write the APP0 JFIF headers if we are stripping.
	 */
	if( strip ) 
		write->cinfo.write_JFIF_header = FALSE;

	/* Build compress tables.
	 */
	jpeg_start_compress( &write->cinfo, TRUE );

	/* Write any APP markers we need.
	 */
	if( !strip ) { 
		if( write_exif( write ) ||
			write_blob( write, 
				VIPS_META_XMP_NAME, JPEG_APP0 + 1 ) ||
			write_blob( write, 
				VIPS_META_IPCT_NAME, JPEG_APP0 + 13 ) )
			return( -1 );

		/* A profile supplied as an argument overrides an embedded 
		 * profile. "none" means don't attach a profile.
		 */
		if( profile && 
			strcmp( profile, "none" ) != 0 &&
			write_profile_file( write, profile ) )
			return( -1 );
		if( !profile && 
			vips_image_get_typeof( in, VIPS_META_ICC_NAME ) && 
			write_profile_meta( write ) )
			return( -1 );
	}

	/* Write data. Note that the write function grabs the longjmp()!
	 */
	if( vips_sink_disc( in, write_jpeg_block, write ) )
		return( -1 );

	/* We have to reinstate the setjmp() before we jpeg_finish_compress().
	 */
	if( setjmp( write->eman.jmp ) ) 
		return( -1 );

	jpeg_finish_compress( &write->cinfo );

	return( 0 );
}

/* Write an image to a jpeg file.
 */
int
vips__jpeg_write_file( VipsImage *in, 
	const char *filename, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip, 
	gboolean no_subsample, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans, int quant_table )
{
	Write *write;

	if( !(write = write_new( in )) )
		return( -1 );

	if( setjmp( write->eman.jmp ) ) {
		/* Here for longjmp() from new_error_exit().
		 */
		write_destroy( write );

		return( -1 );
	}

	/* Can't do this in write_new(), has to be after we've made the
	 * setjmp().
	 */
        jpeg_create_compress( &write->cinfo );

	/* Make output.
	 */
        if( !(write->eman.fp = vips__file_open_write( filename, FALSE )) ) {
		write_destroy( write );
                return( -1 );
        }
        jpeg_stdio_dest( &write->cinfo, write->eman.fp );

	/* Convert!
	 */
	if( write_vips( write, 
		Q, profile, optimize_coding, progressive, strip, no_subsample,
		trellis_quant, overshoot_deringing, optimize_scans, 
		quant_table ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

/* Just like the above, but we write to a memory buffer.
 *
 * A memory buffer for the compressed image.
 */
typedef struct {
	/* Public jpeg fields.
	 */
	struct jpeg_destination_mgr pub;

	/* Private stuff during write.
	 */

	/* Build the output area here.
	 */
	VipsDbuf dbuf;

	/* Write the generated area here.
	 */
	void **obuf;		/* Allocated buffer, and size */
	size_t *olen;
} OutputBuffer;

/* Buffer full method ... allocate a new output block. This is only called 
 * when the output area is exactly full.
 */
METHODDEF(boolean)
empty_output_buffer( j_compress_ptr cinfo )
{
	OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	size_t size;

	vips_dbuf_allocate( &buf->dbuf, 10000 ); 
	buf->pub.next_output_byte = 
		(JOCTET *) vips_dbuf_get_write( &buf->dbuf, &size );
	buf->pub.free_in_buffer = size;

	/* TRUE means we've made some more space.
	 */
	return( 1 );
}

/* Init dest method.
 */
METHODDEF(void)
init_destination( j_compress_ptr cinfo )
{
	OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	vips_dbuf_init( &buf->dbuf ); 
	empty_output_buffer( cinfo ); 
}

/* Cleanup. Copy the set of blocks out as a big lump.
 */
METHODDEF(void)
term_destination( j_compress_ptr cinfo )
{
        OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	size_t size;

	/* We probably won't have filled the area that was last allocated in 
	 * empty_output_buffer(). Chop the data size down to the length that
	 * was actually written.
	 */
	vips_dbuf_seek( &buf->dbuf, -buf->pub.free_in_buffer, SEEK_END );
	vips_dbuf_truncate( &buf->dbuf ); 

	*(buf->obuf) = vips_dbuf_steal( &buf->dbuf, &size );
	*(buf->olen) = size; 
}

/* Set dest to one of our objects.
 */
static void
buf_dest( j_compress_ptr cinfo, void **obuf, size_t *olen )
{
	OutputBuffer *buf;

	/* The destination object is made permanent so that multiple JPEG 
	 * images can be written to the same file without re-executing 
	 * jpeg_stdio_dest. This makes it dangerous to use this manager and 
	 * a different destination manager serially with the same JPEG object,
	 * because their private object sizes may be different.  
	 *
	 * Caveat programmer.
	 */
	if( !cinfo->dest ) {    /* first time for this JPEG object? */
		cinfo->dest = (struct jpeg_destination_mgr *)
			(*cinfo->mem->alloc_small) 
				( (j_common_ptr) cinfo, JPOOL_PERMANENT,
				  sizeof( OutputBuffer ) );
	}

	buf = (OutputBuffer *) cinfo->dest;
	buf->pub.init_destination = init_destination;
	buf->pub.empty_output_buffer = empty_output_buffer;
	buf->pub.term_destination = term_destination;

	/* Save output parameters.
	 */
	buf->obuf = obuf;
	buf->olen = olen;
}

int
vips__jpeg_write_buffer( VipsImage *in, 
	void **obuf, size_t *olen, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive,
	gboolean strip, gboolean no_subsample, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans, int quant_table )
{
	Write *write;

	if( !(write = write_new( in )) )
		return( -1 );

	/* Clear output parameters.
	 */
	*obuf = NULL;
	*olen = 0;

	/* Make jpeg compression object.
 	 */
	if( setjmp( write->eman.jmp ) ) {
		/* Here for longjmp() from new_error_exit().
		 */
		write_destroy( write );

		return( -1 );
	}
        jpeg_create_compress( &write->cinfo );

	/* Attach output.
	 */
        buf_dest( &write->cinfo, obuf, olen );

	/* Convert!
	 */
	if( write_vips( write, 
		Q, profile, optimize_coding, progressive, strip, no_subsample,
		trellis_quant, overshoot_deringing, optimize_scans, 
		quant_table ) ) {
		write_destroy( write );

		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

const char *vips__jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

#endif /*HAVE_JPEG*/
