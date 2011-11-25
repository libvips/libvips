/* save to jpeg
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
 * 	- rework as a class
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
#define VIPS_DEBUG
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
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/buf.h>

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#include "jpeg.h"

typedef struct _VipsFileSaveJpeg {
	VipsFileSave parent_object;

	/* Quality factor.
	 */
	int Q;

	/* Profile to embed .. "none" means don't attach a profile.
	 */
	char *profile;

	/* Stuff we track during write.
	 */
	struct jpeg_compress_struct cinfo;
        ErrorManager eman;
	JSAMPROW *row_pointer;
	char *profile_bytes;
	unsigned int profile_length;

	/* We sometimes need to invert the image before saving.
	 */
	VipsImage *inverted;

} VipsFileSaveJpeg;

typedef VipsFileSaveClass VipsFileSaveJpegClass;

G_DEFINE_TYPE( VipsFileSaveJpeg, vips_file_save_jpeg, VIPS_TYPE_FILE_SAVE );

static void
vips_file_save_jpeg_dispose( GObject *gobject )
{
	VipsFileSaveJpeg *save = (VipsFileSaveJpeg *) gobject;

	VIPS_UNREF( save->inverted );

	G_OBJECT_CLASS( vips_file_save_jpeg_parent_class )->dispose( gobject );
}

static void
vips_file_save_jpeg_finalize( GObject *gobject )
{
	VipsFileSaveJpeg *save = (VipsFileSaveJpeg *) gobject;

	jpeg_destroy_compress( &save->cinfo );
	VIPS_FREEF( fclose, save->eman.fp );
	VIPS_FREE( save->row_pointer );
	VIPS_FREE( save->profile_bytes );

	G_OBJECT_CLASS( vips_file_save_jpeg_parent_class )->finalize( gobject );
}

#ifdef HAVE_EXIF
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
		exif_tag_get_title( entry->tag ), value );

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
vips_exif_set_double( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data )
{
	double value = *((double *) data);

	ExifByteOrder bo;
	size_t sizeof_component;
	size_t offset;

	if( entry->components <= component ) {
		VIPS_DEBUG_MSG( "vips_exif_set_int: too few components\n" );
		return;
	}

	/* Wait until after the component check to make sure we cant get /0.
	 */
	bo = exif_data_get_byte_order( ed );
	sizeof_component = entry->size / entry->components;
	offset = component * sizeof_component;

	VIPS_DEBUG_MSG( "vips_exif_set_double: %s = %g\n",
		exif_tag_get_title( entry->tag ), value );

	if( entry->format == EXIF_FORMAT_RATIONAL ) {
		ExifRational rational;
		unsigned int scale;

		/* We scale up to fill uint32, then set that as the
		 * denominator. Try to avoid generating 0.
		 */
		scale = (int) ((UINT_MAX - 1000) / value);
		scale = scale == 0 ? 1 : scale;
		rational.numerator = value * scale;
		rational.denominator = scale;

		exif_set_rational( entry->data + offset, bo, rational );
	}
	else if( entry->format == EXIF_FORMAT_SRATIONAL ) {
		ExifSRational rational;
		int scale;

		scale = (int) ((INT_MAX - 1000) / value);
		scale = scale == 0 ? 1 : scale;
		rational.numerator = value * scale;
		rational.denominator = scale;

		exif_set_srational( entry->data + offset, bo, rational );
	}
}

typedef void (*write_fn)( ExifData *ed, 
	ExifEntry *entry, unsigned long component, void *data );

/* Write a component in a tag everywhere it appears.
 */
static int
write_tag( ExifData *ed, 
	ExifTag tag, ExifFormat format, write_fn fn, void *data )
{
	int found;
	int i;

	found = 0;
	for( i = 0; i < EXIF_IFD_COUNT; i++ ) {
		ExifEntry *entry;

		if( (entry = exif_content_get_entry( ed->ifd[i], tag )) &&
			entry->format == format ) {
			fn( ed, entry, 0, data );
			found = 1;
		}
	}

	if( !found ) {
		/* There was no tag we could update ... make one in ifd[0].
		 */
		ExifEntry *entry;

		entry = exif_entry_new();

		/* tag must be set before calling exif_content_add_entry.
		 */
		entry->tag = tag; 

		exif_content_add_entry( ed->ifd[0], entry );
		exif_entry_initialize( entry, tag );
		exif_entry_unref( entry );

		fn( ed, entry, 0, data );
	}

	return( 0 );
}

/* This is different, we set the xres/yres from the vips header rather than
 * from the exif tags on the image metadata.
 */
static int
set_exif_resolution( ExifData *ed, VipsImage *im )
{
	double xres, yres;
	int unit;

	/* Always save as inches - more progs support it for read.
	 */
	xres = im->Xres * 25.4;
	yres = im->Yres * 25.4;
	unit = 2;

	if( write_tag( ed, EXIF_TAG_X_RESOLUTION, EXIF_FORMAT_RATIONAL, 
		vips_exif_set_double, (void *) &xres ) ||
		write_tag( ed, EXIF_TAG_Y_RESOLUTION, EXIF_FORMAT_RATIONAL, 
			vips_exif_set_double, (void *) &yres ) ||
		write_tag( ed, EXIF_TAG_RESOLUTION_UNIT, EXIF_FORMAT_SHORT, 
			vips_exif_set_int, (void *) &unit ) ) {
		vips_error( "VipsFileSaveJpeg", 
			"%s", _( "error setting JPEG resolution" ) );
		return( -1 );
	}

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
			entry->format == EXIF_FORMAT_SRATIONAL ) {
			double value = g_ascii_strtod( p, NULL );

			vips_exif_set_double( ed, entry, i, &value );
		}

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

typedef struct _VipsExif {
	VipsImage *image;
	ExifData *ed;
} VipsExif;

static void
vips_exif_update_entry( ExifEntry *entry, VipsExif *ve )
{
	char name[256];
	char *value;

	vips_snprintf( name, 256, "exif-%s", exif_tag_get_title( entry->tag ) );
	if( !vips_image_get_string( ve->image, name, &value ) )
		vips_exif_from_s( ve->ed, entry, value ); 
}

static void
vips_exif_update_content( ExifContent *content, VipsExif *ve )
{
        exif_content_foreach_entry( content, 
		(ExifContentForeachEntryFunc) vips_exif_update_entry, ve );
}

static void
vips_exif_update( ExifData *ed, VipsImage *image )
{
	VipsExif ve;

	VIPS_DEBUG_MSG( "vips_exif_update: \n" );

	ve.image = image;
	ve.ed = ed;
	exif_data_foreach_content( ed, 
		(ExifDataForeachContentFunc) vips_exif_update_content, &ve );
}


#endif /*HAVE_EXIF*/

static int
write_exif( VipsFileSaveJpeg *jpeg )
{
	VipsFileSave *save = (VipsFileSave *) jpeg;

	unsigned char *data;
	size_t data_length;
	unsigned int idl;
#ifdef HAVE_EXIF
	ExifData *ed;

	/* Either parse from the embedded EXIF, or if there's none, make
	 * some fresh EXIF we can write the resolution to.
	 */
	if( vips_image_get_typeof( save->in, VIPS_META_EXIF_NAME ) ) {
		if( vips_image_get_blob( save->in, VIPS_META_EXIF_NAME, 
			(void *) &data, &data_length ) )
			return( -1 );

		if( !(ed = exif_data_new_from_data( data, data_length )) )
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
	vips_exif_update( ed, save->in );

	/* Update EXIF resolution from the vips image header..
	 */
	if( set_exif_resolution( ed, save->in ) ) {
		exif_data_free( ed );
		return( -1 );
	}

	/* Reserialise and write. exif_data_save_data() returns an int for some
	 * reason.
	 */
	exif_data_save_data( ed, &data, &idl );
	if( !idl ) {
		vips_error( "VipsFileSaveJpeg", 
			"%s", _( "error saving EXIF" ) );
		exif_data_free( ed );
		return( -1 );
	}
	data_length = idl;

#ifdef DEBUG
	printf( "jpegsave: attaching %zd bytes of EXIF\n", data_length  );
#endif /*DEBUG*/

	exif_data_free( ed );
	jpeg_write_marker( &jpeg->cinfo, JPEG_APP0 + 1, data, data_length );
	free( data );
#else /*!HAVE_EXIF*/
	/* No libexif ... just copy the embedded EXIF over.
	 */
	if( vips_image_get_typeof( save->in, VIPS_META_EXIF_NAME ) ) {
		if( vips_image_get_blob( save->in, VIPS_META_EXIF_NAME, 
			(void *) &data, &data_length ) )
			return( -1 );

#ifdef DEBUG
		printf( "jpegsave: attaching %zd bytes of EXIF\n", 
			data_length  );
#endif /*DEBUG*/

		jpeg_write_marker( &jpeg->cinfo, JPEG_APP0 + 1, 
			data, data_length );
	}
#endif /*!HAVE_EXIF*/

	return( 0 );
}

static int
write_xmp( VipsFileSaveJpeg *jpeg )
{
	VipsFileSave *save = (VipsFileSave *) jpeg;

	unsigned char *data;
	size_t data_length;

	/* No libexif ... just copy the embedded EXIF over.
	 */
	if( vips_image_get_typeof( save->in, VIPS_META_XMP_NAME ) ) {
		if( vips_image_get_blob( save->in, VIPS_META_XMP_NAME, 
			(void *) &data, &data_length ) )
			return( -1 );

#ifdef DEBUG
		printf( "jpegsave: attaching %zd bytes of XMP\n", 
			data_length  );
#endif /*DEBUG*/

		jpeg_write_marker( &jpeg->cinfo, JPEG_APP0 + 1, 
			data, data_length );
	}

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
write_profile_file( VipsFileSaveJpeg *jpeg, const char *profile )
{
	if( !(jpeg->profile_bytes = 
		vips__file_read_name( profile, VIPS_ICC_DIR, 
			&jpeg->profile_length )) ) 
		return( -1 );
	write_profile_data( &jpeg->cinfo, 
		(JOCTET *) jpeg->profile_bytes, jpeg->profile_length );

#ifdef DEBUG
	printf( "jpegsave: attached profile \"%s\"\n", profile );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_profile_meta( VipsFileSaveJpeg *jpeg )
{
	VipsFileSave *save = (VipsFileSave *) jpeg;

	void *data;
	size_t data_length;

	if( vips_image_get_blob( save->in, VIPS_META_ICC_NAME, 
		&data, &data_length ) )
		return( -1 );

	write_profile_data( &jpeg->cinfo, data, data_length );

#ifdef DEBUG
	printf( "jpegsave: attached %zd byte profile from VIPS header\n",
		data_length );
#endif /*DEBUG*/

	return( 0 );
}

static int
write_jpeg_block( VipsRegion *region, VipsRect *area, void *a )
{
	VipsFileSaveJpeg *jpeg = (VipsFileSaveJpeg *) a;

	int i;

	for( i = 0; i < area->height; i++ )
		jpeg->row_pointer[i] = (JSAMPROW) 
			VIPS_REGION_ADDR( region, 0, area->top + i );

	/* We are running in a background thread. We need to catch any
	 * longjmp()s from jpeg_write_scanlines() here.
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	jpeg_write_scanlines( &jpeg->cinfo, jpeg->row_pointer, area->height );

	return( 0 );
}

/* Write a VIPS image to a JPEG compress struct.
 */
static int
vips_file_save_jpeg_write( VipsFileSaveJpeg *jpeg )
{
	VipsFileSave *save = (VipsFileSave *) jpeg;

	VipsImage *in;
	J_COLOR_SPACE space;

	/* The image we'll be writing ... can change, see CMYK.
	 */
	in = save->ready;

	/* Should have been converted for save.
	 */
        g_assert( in->BandFmt == VIPS_FORMAT_UCHAR );
	g_assert( in->Coding == VIPS_CODING_NONE );
        g_assert( in->Bands == 1 || in->Bands == 3 || in->Bands == 4 );

        /* Check input image.
         */
	if( vips_image_pio_input( in ) )
		return( -1 );

	/* Set compression parameters.
	 */
        jpeg->cinfo.image_width = in->Xsize;
        jpeg->cinfo.image_height = in->Ysize;
	jpeg->cinfo.input_components = in->Bands;
	if( in->Bands == 4 && 
		in->Type == VIPS_INTERPRETATION_CMYK ) {
		space = JCS_CMYK;
		/* IJG always sets an Adobe marker, so we should invert CMYK.
		 */
		if( vips_invert( in, &jpeg->inverted, NULL ) ) 
			return( -1 );
		in = jpeg->inverted;
	}
	else if( in->Bands == 3 )
		space = JCS_RGB;
	else if( in->Bands == 1 )
		space = JCS_GRAYSCALE;
	else 
		/* Use luminance compression for all channels.
		 */
		space = JCS_UNKNOWN;
	jpeg->cinfo.in_color_space = space; 

	/* Build VIPS output stuff now we know the image we'll be writing.
	 */
	if( !(jpeg->row_pointer = VIPS_ARRAY( NULL, in->Ysize, JSAMPROW )) )
		return( -1 );

	/* Rest to default. 
	 */
        jpeg_set_defaults( &jpeg->cinfo );
        jpeg_set_quality( &jpeg->cinfo, jpeg->Q, TRUE );

	/* Build compress tables.
	 */
	jpeg_start_compress( &jpeg->cinfo, TRUE );

	/* Write any APP markers we need.
	 */
	if( write_exif( jpeg ) )
		return( -1 );

	if( write_xmp( jpeg ) )
		return( -1 );

	/* A profile supplied as an argument overrides an embedded profile.
	 * "none" means don't attach a profile.
	 */
	if( jpeg->profile && 
		strcmp( jpeg->profile, "none" ) != 0 &&
		write_profile_file( jpeg, jpeg->profile ) )
		return( -1 );
	if( !jpeg->profile && 
		vips_image_get_typeof( in, VIPS_META_ICC_NAME ) && 
		write_profile_meta( jpeg ) )
		return( -1 );

	/* Write data. Note that the write function grabs the longjmp()!
	 */
	if( vips_sink_disc( in, write_jpeg_block, jpeg ) )
		return( -1 );

	/* We have to reinstate the setjmp() before we jpeg_finish_compress().
	 */
	if( setjmp( jpeg->eman.jmp ) ) 
		return( -1 );

	jpeg_finish_compress( &jpeg->cinfo );

	return( 0 );
}

static int
vips_file_save_jpeg_build( VipsObject *object )
{
	VipsFile *file = (VipsFile *) object;
	VipsFileSaveJpeg *jpeg = (VipsFileSaveJpeg *) object;

	if( VIPS_OBJECT_CLASS( vips_file_save_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	if( setjmp( jpeg->eman.jmp ) ) 
		/* Here for longjmp() from vips__new_error_exit().
		 */
		return( -1 );

	/* Can't do this in init, has to be after we've made the
	 * setjmp().
	 */
        jpeg_create_compress( &jpeg->cinfo );

	/* Make output.
	 */
        if( !(jpeg->eman.fp = vips__file_open_write( file->filename, FALSE )) ) 
                return( -1 );
        jpeg_stdio_dest( &jpeg->cinfo, jpeg->eman.fp );

	/* Convert!
	 */
	if( vips_file_save_jpeg_write( jpeg ) ) 
		return( -1 );

	return( 0 );
}

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static const char *jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

static void
vips_file_save_jpeg_class_init( VipsFileSaveJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsFileClass *) class;
	VipsFileSaveClass *save_class = (VipsFileSaveClass *) class;

	gobject_class->dispose = vips_file_save_jpeg_dispose;
	gobject_class->finalize = vips_file_save_jpeg_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave";
	object_class->description = _( "save image to jpeg file" );
	object_class->build = vips_file_save_jpeg_build;

	file_class->suffs = jpeg_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB_CMYK;
	save_class->format_table = bandfmt_jpeg;

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileSaveJpeg, Q ),
		1, 100, 75 );

	VIPS_ARG_STRING( class, "profile", 11, 
		_( "profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileSaveJpeg, profile ),
		NULL );

}

static void
vips_file_save_jpeg_init( VipsFileSaveJpeg *jpeg )
{
	jpeg->Q = 75;
        jpeg->cinfo.err = jpeg_std_error( &jpeg->eman.pub );
	jpeg->eman.pub.error_exit = vips__new_error_exit;
	jpeg->eman.pub.output_message = vips__new_output_message;
}

