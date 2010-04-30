/* Read a file using MagickWand
 * 
 * 29/4/10
 * 	- from im_magick2vips(), because that API seems to have been
 * 	  deprecated, argh
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

/* Turn on debugging output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifndef HAVE_MAGICK

#include <vips/vips.h>

int
im_magick2vips( const char *filename, IMAGE *im )
{
	im_error( "im_magick2vips", "%s",
		_( "libMagick support disabled" ) );
	return( -1 );
}

#else /*HAVE_MAGICK*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/thread.h>

#include <magick/api.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* pre-float Magick used to call this MaxRGB.
 */
#if !defined(QuantumRange)
#  define QuantumRange MaxRGB
#endif

/* And this used to be UseHDRI.
 */
#if MAGICKCORE_HDRI_SUPPORT
#  define UseHDRI=1
#endif

/* What we track during a read call.
 */
typedef struct _Read {
	char *filename;
	IMAGE *im;

	MagickWand *wand;
	ImageInfo *image_info;
	ExceptionInfo exception;

	int n_frames;
	Image **frames;
	int frame_height;

	/* Mutex to serialise calls to libMagick during threaded read.
	 */
	GMutex *lock;
} Read;

static int
read_destroy( Read *read )
{
#ifdef DEBUG
	printf( "im_magick2vips: read_destroy: %s\n", read->filename );
#endif /*DEBUG*/

	IM_FREEF( DestroyImage, read->image );
	IM_FREEF( DestroyImageInfo, read->image_info ); 
	IM_FREE( read->frames );
	IM_FREE( read->filename );
	DestroyExceptionInfo( &read->exception );
	IM_FREEF( g_mutex_free, read->lock );
	im_free( read );

	return( 0 );
}

static Read *
read_new( const char *filename, IMAGE *im )
{
	Read *read;
	static int inited = 0;

	if( !inited ) {
		InitializeMagick( "" );
		inited = 1;
	}

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );
	read->filename = im_strdup( NULL, filename );
	read->im = im;
	read->image = NULL;
	read->image_info = CloneImageInfo( NULL );
	GetExceptionInfo( &read->exception );
	read->n_frames = 0;
	read->frames = NULL;
	read->frame_height = 0;
	read->lock = g_mutex_new();

	if( im_add_close_callback( im,
		(im_callback_fn) read_destroy, read, NULL ) ) {
		read_destroy( read );
		return( NULL );
	}

	if( !read->filename || !read->image_info ) 
		return( NULL );

	im_strncpy( read->image_info->filename, filename, MaxTextExtent );

#ifdef DEBUG
	printf( "im_magick2vips: read_new: %s\n", read->filename );
#endif /*DEBUG*/

	return( read );
}

static int
get_bands( Image *image )
{
	int bands;

	switch( image->colorspace ) {
	case GRAYColorspace:
		bands = 1;
		break;

	case RGBColorspace:
		bands = 3;
		break;

	case sRGBColorspace:
		bands = 3;
		break;

	case CMYKColorspace:
		bands = 4;
		break;

	default:
		im_error( "im_magick2vips", _( "unsupported colorspace %d" ),
			(int) image->colorspace );
		return( -1 );
	}

	/* Alpha as well?
	 */
	if( image->matte ) {
		assert( image->colorspace != CMYKColorspace );
		bands += 1;
	}

	return( bands );
}

static int
parse_header( Read *read )
{
	IMAGE *im = read->im;
	MagickWand *wand = read->wand;

#ifdef HAVE_MAGICK_ATTR
	const ImageAttribute *attr;
#endif /*HAVE_MAGICK_ATTR*/
	Image *p;
	int i;

	im->Xsize = MagickGetImageWidth( wand );
	im->Ysize = MagickGetImageHeight( wand );
	read->frame_height = MagickGetImageHeight( wand );
	if( (im->Bands = get_bands( image )) < 0 )
		return( -1 );

	/* Depth can be 'fractional'. 
	 */
	depth = MagickGetImageChannelDepth( wand, AllChannels );

	im->BandFmt = -1;
	if( image->depth >= 1 && image->depth <= 8 ) 
		im->BandFmt = IM_BANDFMT_UCHAR;
	if( image->depth >= 9 && image->depth <= 16 ) 
		im->BandFmt = IM_BANDFMT_USHORT;
#ifdef UseHDRI
	if( image->depth == 32 )
		im->BandFmt = IM_BANDFMT_FLOAT;
	if( image->depth == 64 )
		im->BandFmt = IM_BANDFMT_DOUBLE;
#else /*!UseHDRI*/
	if( image->depth == 32 )
		im->BandFmt = IM_BANDFMT_UINT;
#endif /*UseHDRI*/

	if( im->BandFmt == -1 ) {
		im_error( "im_magick2vips", _( "unsupported bit depth %d" ),
			(int) image->depth );
		return( -1 );
	}

	switch( image->colorspace ) {
	case GRAYColorspace:
		if( im->BandFmt == IM_BANDFMT_USHORT )
			im->Type = IM_TYPE_GREY16;
		else
			im->Type = IM_TYPE_B_W;
		break;

	case RGBColorspace:
		if( im->BandFmt == IM_BANDFMT_USHORT )
			im->Type = IM_TYPE_RGB16;
		else
			im->Type = IM_TYPE_RGB;
		break;

	case sRGBColorspace:
		if( im->BandFmt == IM_BANDFMT_USHORT )
			im->Type = IM_TYPE_RGB16;
		else
			im->Type = IM_TYPE_sRGB;
		break;

	case CMYKColorspace:
		im->Type = IM_TYPE_CMYK;
		break;

	default:
		im_error( "im_magick2vips", _( "unsupported colorspace %d" ),
			(int) image->colorspace );
		return( -1 );
	}

	switch( image->units ) {
	case PixelsPerInchResolution:
		im->Xres = image->x_resolution / 25.4;
		im->Yres = image->y_resolution / 25.4;
		break;

	case PixelsPerCentimeterResolution:
		im->Xres = image->x_resolution / 10.0;
		im->Yres = image->y_resolution / 10.0;
		break;

	default:
		im->Xres = 1.0;
		im->Yres = 1.0;
		break;
	}

	/* Other fields.
	 */
	im->Coding = IM_CODING_NONE;

#ifdef HAVE_MAGICK_ATTR
#ifdef HAVE_GETNEXTIMAGEATTRIBUTE
	/* Gah, magick6.something and later only. Attach any attributes.
	 */
	ResetImageAttributeIterator( image );
	while( (attr = GetNextImageAttribute( image )) ) {
#elif defined(HAVE_GETIMAGEATTRIBUTE)
	/* GraphicsMagick is missing the iterator: we have to loop ourselves.
	 * ->attributes is marked as private in the header, but there's no
	 * getter so we have to access it directly.
	 */
	for( attr = image->attributes; attr; attr = attr->next ) {
#else /*stuff*/
	#error attributes enabled, but no access funcs found
#endif
		char name_text[256];
		VipsBuf name;

		vips_buf_init_static( &name, name_text, 256 );
		vips_buf_appendf( &name, "magick-%s", attr->key );
		im_meta_set_string( im, vips_buf_all( &name ), attr->value );

#ifdef DEBUG
		printf( "key = \"%s\", value = \"%s\"\n", 
			attr->key, attr->value );
#endif /*DEBUG*/
	}
#endif /*HAVE_MAGICK_ATTR*/

	/* Do we have a set of equal-sized frames? Append them.

	   	FIXME ... there must be an attribute somewhere from dicom read 
		which says this is a volumetric image

	 */
	read->n_frames = 0;
	for( p = image; p; (p = GetNextImageInList( p )) ) {
		if( p->columns != (unsigned int) im->Xsize ||
			p->rows != (unsigned int) im->Ysize ||
			get_bands( p ) != im->Bands )
			break;

		read->n_frames += 1;
	}
	if( p ) 
		/* Nope ... just do the first image in the list.
		 */
		read->n_frames = 1;

	/* Record frame pointers.
	 */
	im->Ysize *= read->n_frames;
	if( !(read->frames = IM_ARRAY( NULL, read->n_frames, Image * )) )
		return( -1 );
	p = image;
	for( i = 0; i < read->n_frames; i++ ) {
		read->frames[i] = p;
		p = GetNextImageInList( p );
	}

	return( 0 );
}

static int
magickwand2vips_header( const char *filename, IMAGE *im )
{
	Read *read;

	if( !(read = read_new( filename, im )) )
		return( -1 );

	read->image = PingImage( read->image_info, &read->exception );
	if( !read->image ) {
		im_error( "im_magick2vips", _( "unable to ping file "
			"\"%s\"\nlibMagick error: %s %s" ),
			filename, 
			read->exception.reason, read->exception.description );
		return( -1 );
	}

	if( parse_header( read ) ) 
		return( -1 );

	if( im->Xsize <= 0 || im->Ysize <= 0 ) {
		im_error( "im_magick2vips", "%s", _( "bad image size" ) );
		return( -1 );
	}

	return( 0 );
}

static int
ismagickwand( const char *filename )
{
	IMAGE *im;
	int result;

	if( !(im = im_open( "dummy", "p" )) )
		return( -1 );
	result = magickwand2vips_header( filename, im );
	im_error_clear();
	im_close( im );

	return( result == 0 );
}

static const char *magick_suffs[] = { NULL };

/* magick format adds no new members.
 */
typedef VipsFormat VipsFormatMagickWand;
typedef VipsFormatClass VipsFormatMagickWandClass;

static void
vips_format_magickwand_class_init( VipsFormatMagickWandClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "magickwand";
	object_class->description = _( "MagickWand-supported" );

	format_class->is_a = ismagickwand;
	format_class->header = magickwand2vips_header;
	//format_class->load = im_magickwand2vips;
	format_class->suffs = magickwand_suffs;

	/* This can be very slow :-( Use our own jpeg/tiff/png etc. loaders in
	 * preference, if we can.
	 */
	format_class->priority = -1000;
}

static void
vips_format_magickwand_init( VipsFormatMagickWand *object )
{
}

G_DEFINE_TYPE( VipsFormatMagickWand, vips_format_magickwand, VIPS_TYPE_FORMAT );

#endif /*HAVE_MAGICK*/
