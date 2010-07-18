/* Convert 8-bit VIPS images to/from JPEG.
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
im_vips2jpeg( IMAGE *in, const char *filename )
{
	im_error( "im_vips2jpeg", "%s",
		_( "JPEG support disabled" ) );

	return( -1 );
}

int
im_vips2bufjpeg( IMAGE *in, IMAGE *out, int qfac, char **obuf, int *olen )
{
	im_error( "im_vips2bufjpeg", "%s",
		_( "JPEG support disabled" ) );

	return( -1 );
}

int
im_vips2mimejpeg( IMAGE *in, int qfac )
{
	im_error( "im_vips2mimejpeg", "%s",
		_( "JPEG support disabled" ) );

	return( -1 );
}

#else /*HAVE_JPEG*/

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
#include <vips/internal.h>
#include <vips/buf.h>

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

/* What we track during a JPEG write.
 */
typedef struct {
	IMAGE *in;
	struct jpeg_compress_struct cinfo;
        ErrorManager eman;
	JSAMPROW *row_pointer;
	char *profile_bytes;
	unsigned int profile_length;
	IMAGE *inverted;
} Write;

static void
write_destroy( Write *write )
{
	jpeg_destroy_compress( &write->cinfo );
	IM_FREEF( im_close, write->in );
	IM_FREEF( fclose, write->eman.fp );
	IM_FREE( write->row_pointer );
	IM_FREE( write->profile_bytes );
	IM_FREEF( im_close, write->inverted );
	im_free( write );
}

#define UC IM_BANDFMT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static Write *
write_new( IMAGE *in )
{
	Write *write;

	if( !(write = IM_NEW( NULL, Write )) )
		return( NULL );
	memset( write, 0, sizeof( Write ) );

	if( !(write->in = im__convert_saveable( in, 
		IM__RGB_CMYK, bandfmt_jpeg )) ) {
		im_error( "im_vips2jpeg", 
			"%s", _( "unable to convert to saveable format" ) );
		write_destroy( write );
		return( NULL );
	} 
	write->row_pointer = NULL;
        write->cinfo.err = jpeg_std_error( &write->eman.pub );
	write->eman.pub.error_exit = new_error_exit;
	write->eman.pub.output_message = new_output_message;
	write->eman.fp = NULL;
	write->profile_bytes = NULL;
	write->profile_length = 0;
	write->inverted = NULL;

        return( write );
}

#ifdef HAVE_EXIF
static void
write_rational( ExifEntry *entry, ExifByteOrder bo, void *data )
{
	ExifRational *v = (ExifRational *) data;

	exif_set_rational( entry->data, bo, *v );
}

static void
write_short( ExifEntry *entry, ExifByteOrder bo, void *data )
{
	ExifShort *v = (ExifShort *) data;

	exif_set_short( entry->data, bo, *v );
}

typedef void (*write_fn)( ExifEntry *, ExifByteOrder, void * );

static int
write_tag( ExifData *ed, ExifTag tag, ExifFormat f, write_fn fn, void *data )
{
	ExifByteOrder bo;
	int found;
	int i;

	bo = exif_data_get_byte_order( ed );

	/* Need to set the tag in all sections which have it :-(
	 */
	found = 0;
	for( i = 0; i < EXIF_IFD_COUNT; i++ ) {
		ExifEntry *entry;

		if( (entry = exif_content_get_entry( ed->ifd[i], tag )) &&
			entry->format == f &&
			entry->components == 1 ) {
			fn( entry, bo, data );
			found = 1;
		}
	}

	if( !found ) {
		/* There was no tag we could update ... make one in ifd[0].
		 */
		ExifEntry *entry;

		entry = exif_entry_new();
		exif_content_add_entry( ed->ifd[0], entry );
		exif_entry_initialize( entry, tag );
		fn( entry, bo, data );
	}

	return( 0 );
}

static int
set_exif_resolution( ExifData *ed, IMAGE *im )
{
	double xres, yres;
	ExifRational xres_rational, yres_rational;
	ExifShort unit;

	/* Always save as inches - more progs support it for read.
	 */
	xres = im->Xres * 25.4;
	yres = im->Yres * 25.4;
	unit = 2;

	/* Wow, how dumb, fix this.
	 */
	xres_rational.numerator = xres * 100000;
	xres_rational.denominator = 100000;
	yres_rational.numerator = yres * 100000;
	yres_rational.denominator = 100000;

	if( write_tag( ed, EXIF_TAG_X_RESOLUTION, EXIF_FORMAT_RATIONAL, 
		write_rational, &xres_rational ) ||
		write_tag( ed, EXIF_TAG_Y_RESOLUTION, EXIF_FORMAT_RATIONAL, 
			write_rational, &yres_rational ) ||
		write_tag( ed, EXIF_TAG_RESOLUTION_UNIT, EXIF_FORMAT_SHORT, 
			write_short, &unit ) ) {
		im_error( "im_jpeg2vips", 
			"%s", _( "error setting JPEG resolution" ) );
		return( -1 );
	}

	return( 0 );
}
#endif /*HAVE_EXIF*/

static int
write_exif( Write *write )
{
	unsigned char *data;
	size_t data_length;
	unsigned int idl;
#ifdef HAVE_EXIF
	ExifData *ed;

	/* Either parse from the embedded EXIF, or if there's none, make
	 * some fresh EXIF we can write the resolution to.
	 */
	if( im_header_get_typeof( write->in, IM_META_EXIF_NAME ) ) {
		if( im_meta_get_blob( write->in, IM_META_EXIF_NAME, 
			(void *) &data, &data_length ) )
			return( -1 );

		if( !(ed = exif_data_new_from_data( data, data_length )) )
			return( -1 );
	}
	else 
		ed = exif_data_new();

	/* Set EXIF resolution from VIPS.
	 */
	if( set_exif_resolution( ed, write->in ) ) {
		exif_data_free( ed );
		return( -1 );
	}

	/* Reserialise and write. exif_data_save_data() returns an int for some
	 * reason.
	 */
	exif_data_save_data( ed, &data, &idl );
	if( !idl ) {
		im_error( "im_jpeg2vips", "%s", _( "error saving EXIF" ) );
		exif_data_free( ed );
		return( -1 );
	}
	data_length = idl;

#ifdef DEBUG
	printf( "im_vips2jpeg: attaching %zd bytes of EXIF\n", data_length  );
#endif /*DEBUG*/

	exif_data_free( ed );
	jpeg_write_marker( &write->cinfo, JPEG_APP0 + 1, data, data_length );
	free( data );
#else /*!HAVE_EXIF*/
	/* No libexif ... just copy the embedded EXIF over.
	 */
	if( im_header_get_typeof( write->in, IM_META_EXIF_NAME ) ) {
		if( im_meta_get_blob( write->in, IM_META_EXIF_NAME, 
			(void *) &data, &data_length ) )
			return( -1 );

#ifdef DEBUG
		printf( "im_vips2jpeg: attaching %d bytes of EXIF\n", 
			data_length  );
#endif /*DEBUG*/

		jpeg_write_marker( &write->cinfo, JPEG_APP0 + 1, 
			data, data_length );
	}
#endif /*!HAVE_EXIF*/

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
		im__file_read_name( profile, VIPS_ICC_DIR, 
		&write->profile_length )) ) 
		return( -1 );
	write_profile_data( &write->cinfo, 
		(JOCTET *) write->profile_bytes, write->profile_length );

#ifdef DEBUG
	printf( "im_vips2jpeg: attached profile \"%s\"\n", profile );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_profile_meta( Write *write )
{
	void *data;
	size_t data_length;

	if( im_meta_get_blob( write->in, IM_META_ICC_NAME, 
		&data, &data_length ) )
		return( -1 );

	write_profile_data( &write->cinfo, data, data_length );

#ifdef DEBUG
	printf( "im_vips2jpeg: attached %zd byte profile from VIPS header\n",
		data_length );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_jpeg_block( REGION *region, Rect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	/* We are running in a background thread. We need to catch longjmp()s
	 * here instead.
	 */
	if( setjmp( write->eman.jmp ) ) 
		return( -1 );

	for( i = 0; i < area->height; i++ )
		write->row_pointer[i] = (JSAMPROW) 
			IM_REGION_ADDR( region, 0, area->top + i );

	jpeg_write_scanlines( &write->cinfo, write->row_pointer, area->height );

	return( 0 );
}

/* Write a VIPS image to a JPEG compress struct.
 */
static int
write_vips( Write *write, int qfac, const char *profile )
{
	IMAGE *in;
	J_COLOR_SPACE space;

	/* The image we'll be writing ... can change, see CMYK.
	 */
	in = write->in;

	/* Should have been converted for save.
	 */
        g_assert( in->BandFmt == IM_BANDFMT_UCHAR );
	g_assert( in->Coding == IM_CODING_NONE );
        g_assert( in->Bands == 1 || in->Bands == 3 || in->Bands == 4 );

        /* Check input image.
         */
	if( im_pincheck( in ) )
		return( -1 );
        if( qfac < 0 || qfac > 100 ) {
                im_error( "im_vips2jpeg", 
			"%s", _( "qfac should be in 0-100" ) );
                return( -1 );
        }

	/* Set compression parameters.
	 */
        write->cinfo.image_width = in->Xsize;
        write->cinfo.image_height = in->Ysize;
	write->cinfo.input_components = in->Bands;
	if( in->Bands == 4 && in->Type == IM_TYPE_CMYK ) {
		space = JCS_CMYK;
		/* IJG always sets an Adobe marker, so we should invert CMYK.
		 */
		if( !(write->inverted = im_open( "vips2jpeg_invert", "p" )) ||
			im_invert( in, write->inverted ) )
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
	if( !(write->row_pointer = 
		IM_ARRAY( NULL, write->in->Ysize, JSAMPROW )) )
		return( -1 );

	/* Rest to default. 
	 */
        jpeg_set_defaults( &write->cinfo );
        jpeg_set_quality( &write->cinfo, qfac, TRUE );

	/* Build compress tables.
	 */
	jpeg_start_compress( &write->cinfo, TRUE );

	/* Write any APP markers we need.
	 */
	if( write_exif( write ) )
		return( -1 );

	/* A profile supplied as an argument overrides an embedded profile.
	 * "none" means don't attach a profile.
	 */
	if( profile && 
		strcmp( profile, "none" ) != 0 &&
		write_profile_file( write, profile ) )
		return( -1 );
	if( !profile && 
		im_header_get_typeof( in, IM_META_ICC_NAME ) && 
		write_profile_meta( write ) )
		return( -1 );

	/* Write data. Note that the write function grabs the longjmp()!
	 */
	if( vips_sink_disc( write->in, write_jpeg_block, write ) )
		return( -1 );

	/* We have to reinstate the setjmp() before we jpeg_finish_compress().
	 */
	if( setjmp( write->eman.jmp ) ) 
		return( -1 );

	jpeg_finish_compress( &write->cinfo );

	return( 0 );
}

/**
 * im_vips2jpeg:
 * @in: image to save 
 * @filename: file to write to 
 *
 * Write a VIPS image to a file as JPEG.
 *
 * You can embed options in the filename. They have the form:
 *
 * |[
 * filename.jpg:<emphasis>compression</emphasis>,<emphasis>profile</emphasis>
 * ]|
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * <emphasis>compression</emphasis> 
 * Compress with this quality factor. Default 75.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>profile</emphasis> 
 * Attach this ICC profile. For example, "fred.jpg:,/home/john/srgb.icc" will 
 * embed the profile stored in the file "/home/john/srgb.icc" in the JPEG 
 * image. This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * If no profile is specified in the save string and the VIPS header 
 * contains an ICC profile named IM_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * The image is automatically converted to RGB, Monochrome or CMYK before 
 * saving. Any metadata attached to the image is saved as EXIF, if possible.
 *
 * Example:
 *
 * |[
 * im_vips2jpeg( in, "fred.jpg:99,none" );
 * ]|
 *
 * Will write "fred.jpg" at high-quality with no ICC profile.
 *
 * See also: #VipsFormat, im_jpeg2vips().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2jpeg( IMAGE *in, const char *filename )
{
	Write *write;
	int qfac = 75; 
	char *profile = NULL;

	char *p, *q;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	/* Parse mode from filename.
	 */
	im_filename_split( filename, name, mode );
	strcpy( buf, mode ); 
	p = &buf[0];
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 )
			qfac = atoi( mode );
	}
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 ) 
			profile = q;
	}
	if( (q = im_getnextoption( &p )) ) {
		im_error( "im_vips2jpeg", 
			_( "unknown extra options \"%s\"" ), q );
		return( -1 );
	}

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
        if( !(write->eman.fp = im__file_open_write( name )) ) {
		write_destroy( write );
                return( -1 );
        }
        jpeg_stdio_dest( &write->cinfo, write->eman.fp );

	/* Convert!
	 */
	if( write_vips( write, qfac, profile ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

/* We can't predict how large the output buffer we need is, because we might
 * need space for ICC profiles and stuff. So we write to a linked list of mem
 * buffers and add a new one as they fill.
 */

#define BUFFER_SIZE (10000)

/* A buffer.
 */
typedef struct _Block {
	j_compress_ptr cinfo;

	struct _Block *first;
	struct _Block *next;

	JOCTET *data;		/* Allocated area */
	int size;		/* Max size */
	int used;		/* How much has been used */
} Block;

static Block *
block_new( j_compress_ptr cinfo )
{
	Block *block;

	block = (Block *) (*cinfo->mem->alloc_large) 
		( (j_common_ptr) cinfo, JPOOL_IMAGE, sizeof( Block ) );

	block->cinfo = cinfo;
	block->first = block;
	block->next = NULL;
	block->data = (JOCTET *) (*cinfo->mem->alloc_large) 
		( (j_common_ptr) cinfo, JPOOL_IMAGE, BUFFER_SIZE );
	block->size = BUFFER_SIZE;
	block->used = 0;

	return( block );
}

static Block *
block_last( Block *block )
{
	while( block->next )
		block = block->next;

	return( block );
}

static Block *
block_append( Block *block )
{
	Block *new;

	g_assert( block );

	new = block_new( block->cinfo );
	new->first = block->first;
	block_last( block )->next = new;

	return( new );
}

static int
block_length( Block *block )
{
	int len;

	len = 0;
	for( block = block->first; block; block = block->next )
		len += block->used;

	return( len );
}

static void
block_copy( Block *block, void *dest )
{
	JOCTET *p;
	
	p = dest;
	for( block = block->first; block; block = block->next ) {
		memcpy( p, block->data, block->used );
		p += block->used;
	}
}

#ifdef DEBUG
static void
block_print( Block *block )
{
	int i;

	printf( "total length = %d\n", block_length( block ) );
	printf( "set of blocks:\n" );

	i = 0;
	for( block = block->first; block; block = block->next ) {
		printf( "%d) %p, first = %p, next = %p"
			"\t data = %p, size = %d, used = %d\n", 
			i, block, block->first, block->next,
			block->data, block->size, block->used );
		i += 1;
	}
}
#endif /*DEBUG*/

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

	/* Build the output area here in chunks.
	 */
	Block *block;

	/* Copy the compressed area here.
	 */
	IMAGE *out;		/* Allocate relative to this */
	char **obuf;		/* Allocated buffer, and size */
	int *olen;
} OutputBuffer;

/* Init dest method.
 */
METHODDEF(void)
init_destination( j_compress_ptr cinfo )
{
	OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	/* Allocate relative to the image we are writing .. freed when we junk
	 * this output.
	 */
	buf->block = block_new( cinfo );

	/* Set buf pointers for library.
	 */
	buf->pub.next_output_byte = buf->block->data;
	buf->pub.free_in_buffer = buf->block->size;
}

/* Buffer full method ... allocate a new output block.
 */
METHODDEF(boolean)
empty_output_buffer( j_compress_ptr cinfo )
{
	OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	/* Record how many bytes we used. empty_output_buffer() is always
	 * called when the buffer is exactly full.
	 */
	buf->block->used = buf->block->size;

	/* New block and reset.
	 */
	buf->block = block_append( buf->block );
	buf->pub.next_output_byte = buf->block->data;
	buf->pub.free_in_buffer = buf->block->size;

	/* TRUE means we've made some more space.
	 */
	return( 1 );
}

/* Cleanup. Copy the set of blocks out as a big lump.
 */
METHODDEF(void)
term_destination( j_compress_ptr cinfo )
{
        OutputBuffer *buf = (OutputBuffer *) cinfo->dest;

	int len;
	void *obuf;

	/* Record the number of bytes we wrote in the final buffer.
	 * pub.free_in_buffer is valid here.
	 */
	buf->block->used = buf->block->size - buf->pub.free_in_buffer;

#ifdef DEBUG
	block_print( buf->block );
#endif /*DEBUG*/

	/* ... and we can count up our buffers now.
	 */
	len = block_length( buf->block );

	/* Allocate and copy to the output area.
	 */
	if( !(obuf = im_malloc( buf->out, len )) )
		ERREXIT( cinfo, JERR_FILE_WRITE );
	*(buf->obuf) = obuf;
	*(buf->olen) = len;

	block_copy( buf->block, obuf );
}

/* Set dest to one of our objects.
 */
static void
buf_dest( j_compress_ptr cinfo, IMAGE *out, char **obuf, int *olen )
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
	buf->out = out;
	buf->obuf = obuf;
	buf->olen = olen;
}

/**
 * im_vips2bufjpeg:
 * @in: image to save 
 * @out: allocate output buffer local to this
 * @qfac: JPEG quality factor
 * @obuf: return output buffer here
 * @olen: return output length here
 *
 * As im_vips2jpeg(), but save as a memory buffer. The memory is allocated
 * local to @out (that is, when @out is closed the memory will be released,
 * pass %NULL to release yourself). 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. @olen should really be a size_t rather than an int :-(
 *
 * See also: #VipsFormat, im_vips2jpeg().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2bufjpeg( IMAGE *in, IMAGE *out, int qfac, char **obuf, int *olen )
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
        buf_dest( &write->cinfo, out, obuf, olen );

	/* Convert!
	 */
	if( write_vips( write, qfac, NULL ) ) {
		write_destroy( write );

		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

/**
 * im_vips2mimejpeg:
 * @in: image to save 
 * @qfac: JPEG quality factor
 *
 * As im_vips2jpeg(), but save as a mime jpeg on stdout.
 *
 * See also: #VipsFormat, im_vips2jpeg().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2mimejpeg( IMAGE *in, int qfac )
{
	IMAGE *base;
	int len;
	char *buf;

	if( !(base = im_open( "im_vips2mimejpeg:1", "p" )) )
		return( -1 );
	if( im_vips2bufjpeg( in, base, qfac, &buf, &len ) ) {
		im_close( base );
		return( -1 );
	}

	/* Write as a MIME type.
	 */
	printf( "Content-length: %d\r\n", len );
	printf( "Content-type: image/jpeg\r\n" );
	printf( "\r\n" );
	if( fwrite( buf, sizeof( char ), len, stdout ) != (size_t) len ) {
		im_error( "im_vips2mimejpeg", 
			"%s", _( "error writing output" ) );
		return( -1 );
	}

	fflush( stdout );
	im_close( base );

	return( 0 );
}

#endif /*HAVE_JPEG*/
