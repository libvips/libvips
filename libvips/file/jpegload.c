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

typedef struct _VipsFileLoadJpeg {
	VipsFileLoad parent_object;

	/* Shrink by this much during load.
	 */
	int shrink;

	/* Fail on first warning.
	 */
	gboolean fail;

} VipsFileLoadJpeg;

typedef VipsFileLoadJpegClass VipsFileLoadJpeg;

G_DEFINE_TYPE( VipsFileLoadJpeg, vips_file_load_jpeg, VIPS_TYPE_FILE_LOAD );

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
	im_error( "VipsFileLoadJpeg", _( "%s" ), buffer );

#ifdef DEBUG
	printf( "VipsFileLoadJpeg: new_output_message: \"%s\"\n", buffer );
#endif /*DEBUG*/
}

/* New error_exit handler.
 */
METHODDEF(void)
new_error_exit( j_common_ptr cinfo )
{
	ErrorManager *eman = (ErrorManager *) cinfo->err;

#ifdef DEBUG
	printf( "VipsFileLoadJpeg: new_error_exit\n" );
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
vips_file_load_jpeg_build( VipsObject *object )
{
	VipsFileLoadJpeg *jpeg = (VipsFileLoadJpeg *) object;

	if( jpeg->shrink != 1 && 
		jpeg->shrink != 2 && 
		jpeg->shrink != 4 && 
		jpeg->shrink != 8 ) {
		vips_error( "VipsFormatLoadJpeg", 
			_( "bad shrink factor %d" ), jpeg->shrink );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( vips_file_load_jpeg_parent_class )->
		build( object ) )
		return( -1 );



	return( 0 );
}

static void
vips_file_load_jpeg_class_init( VipsFileLoadJpegClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "jpegload";
	object_class->description = _( "load jpeg from file" );
	object_class->build = vips_file_load_jpeg_build;

	VIPS_ARG_INT( class, "shrink", 5, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileLoadJpeg, shrink ),
		1, 16, 1 );

	VIPS_ARG_BOOL( class, "fail", 6, 
		_( "Fail" ), 
		_( "Fail on first warning" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileLoadJpeg, fail ),
		FALSE );

}

static void
vips_file_load_jpeg_init( VipsFileLoadJpeg *object )
{
	jpeg->shrink = 1;
}



