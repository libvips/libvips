/* load with libMagick7
 *
 * 8/7/16
 * 	- from magickload
 * 25/11/16
 * 	- add @n, deprecate @all_frames (just sets n = -1)
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef HAVE_MAGICK7

#include <MagickCore/MagickCore.h>

typedef struct _VipsForeignLoadMagick7 {
	VipsForeignLoad parent_object;

	/* Deprecated. Just sets n = -1.
	 */
	gboolean all_frames;

	char *density;			/* Load at this resolution */
	int page;			/* Load this page (frame) */
	int n;				/* Load this many pages */

	Image *image;
	ImageInfo *image_info;
	ExceptionInfo *exception;

	int n_frames;			/* Number of frames in file */
	Image **frames;			/* An Image* for each frame */
	CacheView **cache_view; 	/* A CacheView for each frame */
	int frame_height;	

	/* Mutex to serialise calls to libMagick during threaded read.
	 */
	GMutex *lock;

} VipsForeignLoadMagick7;

typedef VipsForeignLoadClass VipsForeignLoadMagick7Class;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadMagick7, vips_foreign_load_magick7, 
	VIPS_TYPE_FOREIGN_LOAD );

#ifdef DEBUG
static void
vips_magick7_print_traits( Image *image ) 
{
	static const int trait_bits[] = {
		CopyPixelTrait,
		UpdatePixelTrait,
		BlendPixelTrait
	};
	static const char *trait_names[] = {
		"CopyPixelTrait",
		"UpdatePixelTrait",
		"BlendPixelTrait"
	};

	int b; 
	int i; 

	printf( "vips_magick7_print_traits: channel traits:\n" ); 
	for( b = 0; b < GetPixelChannels( image ); b++ ) { 
		PixelChannel channel = 
			GetPixelChannelChannel( image, b ); 
		PixelTrait traits = 
			GetPixelChannelTraits( image, channel );
		
		printf( "\t%d) ", b ); 
		for( i = 0; i < VIPS_NUMBER( trait_bits ); i++ )
			if( traits & trait_bits[i] )
				printf( "%s ", trait_names[i] ); 
		if( traits == 0 )
			printf( "undefined" ); 
		printf( "\n" ); 
	} 
}

static void
vips_magick7_print_channel_names( Image *image )
{
	static const int pixel_channels[] = {
		UndefinedPixelChannel, 
		RedPixelChannel, 
		CyanPixelChannel, 
		GrayPixelChannel, 
		LPixelChannel, 
		LabelPixelChannel, 
		YPixelChannel, 
		aPixelChannel, 
		GreenPixelChannel, 
		MagentaPixelChannel, 
		CbPixelChannel, 
		bPixelChannel, 
		BluePixelChannel, 
		YellowPixelChannel, 
		CrPixelChannel, 
		BlackPixelChannel, 
		AlphaPixelChannel, 
		IndexPixelChannel, 
		ReadMaskPixelChannel, 
		WriteMaskPixelChannel, 
		MetaPixelChannel, 
		IntensityPixelChannel, 
		CompositePixelChannel, 
		SyncPixelChannel
	};
	static const char *pixel_channel_names[] = {
		"UndefinedPixelChannel", 
		"RedPixelChannel", 
		"CyanPixelChannel", 
		"GrayPixelChannel", 
		"LPixelChannel", 
		"LabelPixelChannel", 
		"YPixelChannel", 
		"aPixelChannel", 
		"GreenPixelChannel", 
		"MagentaPixelChannel", 
		"CbPixelChannel", 
		"bPixelChannel", 
		"BluePixelChannel", 
		"YellowPixelChannel", 
		"CrPixelChannel", 
		"BlackPixelChannel", 
		"AlphaPixelChannel", 
		"IndexPixelChannel", 
		"ReadMaskPixelChannel", 
		"WriteMaskPixelChannel", 
		"MetaPixelChannel", 
		"IntensityPixelChannel", 
		"CompositePixelChannel", 
		"SyncPixelChannel", 
	};

	int b; 
	int i; 

	printf( "vips_magick7_print_channel_names: channel names:\n" ); 
	for( b = 0; b < GetPixelChannels( image ); b++ ) { 
		PixelChannel channel = 
			GetPixelChannelChannel( image, b ); 
		
		printf( "\t%d) ", b ); 
		for( i = 0; i < VIPS_NUMBER( pixel_channels ); i++ )
			/* Don't break on found, many channel names repeat.
			 */
			if( channel == pixel_channels[i] ) 
				printf( "%s ", pixel_channel_names[i] );
		printf( "\n" ); 
	} 
}

static void
vips_magick7_print_image_type( Image *image )
{
	static const int image_types[] = {
		UndefinedType,
		BilevelType,
		GrayscaleType,
		GrayscaleAlphaType, 
		PaletteType,
		PaletteAlphaType,
		TrueColorType,
		TrueColorAlphaType,
		ColorSeparationType,
		ColorSeparationAlphaType,
		OptimizeType,
		PaletteBilevelAlphaType
	};

	static const char *image_type_names[] = {
		"UndefinedType",
		"BilevelType",
		"GrayscaleType",
		"GrayscaleAlphaType", 
		"PaletteType",
		"PaletteAlphaType",
		"TrueColorType",
		"TrueColorAlphaType",
		"ColorSeparationType",
		"ColorSeparationAlphaType",
		"OptimizeType",
		"PaletteBilevelAlphaType"
	};

	int i;

	for( i = 0; i < VIPS_NUMBER( image_types ); i++ ) 
		if( GetImageType( image ) == image_types[i] ) {
			printf( "\t%s\n", image_type_names[i] );
			break;
		}
	if( i == VIPS_NUMBER( image_types ) )
		printf( "\tunknown GetImageType()\n" ); 
}
#endif /*DEBUG*/

static VipsForeignFlags
vips_foreign_load_magick7_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_magick7_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static void
vips_foreign_load_magick7_dispose( GObject *gobject )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) gobject;

	int i;

#ifdef DEBUG
	printf( "vips_foreign_load_magick7_dispose: %p\n", gobject ); 
#endif /*DEBUG*/

	for( i = 0; i < magick7->n_frames; i++ ) {
		VIPS_FREEF( DestroyCacheView, magick7->cache_view[i] ); 
	}
	VIPS_FREEF( DestroyImageList, magick7->image );
	VIPS_FREEF( DestroyImageInfo, magick7->image_info ); 
	VIPS_FREE( magick7->frames );
	VIPS_FREE( magick7->cache_view );
	VIPS_FREEF( DestroyExceptionInfo, magick7->exception ); 
	VIPS_FREEF( vips_g_mutex_free, magick7->lock );

	G_OBJECT_CLASS( vips_foreign_load_magick7_parent_class )->
		dispose( gobject );
}

static void *
vips_foreign_load_magick7_genesis_cb( void *client )
{
#ifdef DEBUG
	printf( "vips_foreign_load_magick7_genesis:\n" ); 
#endif /*DEBUG*/

	MagickCoreGenesis( vips_get_argv0(), MagickFalse );

	return( NULL );
}

static void
vips_foreign_load_magick7_genesis( void )
{
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, vips_foreign_load_magick7_genesis_cb, NULL );
}

static int
vips_foreign_load_magick7_build( VipsObject *object )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) object;

#ifdef DEBUG
	printf( "vips_foreign_load_magick7_build: %p\n", object ); 
#endif /*DEBUG*/

	vips_foreign_load_magick7_genesis();

	magick7->image_info = CloneImageInfo( NULL );
	magick7->exception = AcquireExceptionInfo();
	magick7->lock = vips_g_mutex_new();

	if( !magick7->image_info ) 
		return( -1 );

	if( magick7->all_frames )
		magick7->n = -1;

	/* Canvas resolution for rendering vector formats like SVG.
	 */
	VIPS_SETSTR( magick7->image_info->density, magick7->density );

	/* When reading DICOM images, we want to ignore any
	 * window_center/_width setting, since it may put pixels outside the
	 * 0-65535 range and lose data. 
	 *
	 * These window settings are attached as vips metadata, so our caller
	 * can interpret them if it wants.
	 */
  	SetImageOption( magick7->image_info, "dcm:display-range", "reset" );

	if( magick7->page > 0 ) { 
		 /* I can't find docs for these fields, but this seems to work.
		  */
		char page[256];

		magick7->image_info->scene = magick7->page;
		magick7->image_info->number_scenes = magick7->n;

		vips_snprintf( page, 256, "%d-%d", 
			magick7->page, magick7->page + magick7->n );
		magick7->image_info->scenes = strdup( page );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_magick7_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_magick7_class_init( VipsForeignLoadMagick7Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_magick7_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_base";
	object_class->description = _( "load with ImageMagick7" );
	object_class->build = vips_foreign_load_magick7_build;

	/* We need to be well to the back of the queue since vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->get_flags_filename = 
		vips_foreign_load_magick7_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick7_get_flags;

	VIPS_ARG_BOOL( class, "all_frames", 3, 
		_( "all_frames" ), 
		_( "Read all frames from an image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, all_frames ),
		FALSE );

	VIPS_ARG_STRING( class, "density", 4,
		_( "Density" ),
		_( "Canvas resolution for rendering vector formats like SVG" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, density ),
		NULL );

	VIPS_ARG_INT( class, "page", 5,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 6,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, n ),
		-1, 100000, 1 );

}

static void
vips_foreign_load_magick7_init( VipsForeignLoadMagick7 *magick7 )
{
	magick7->n = 1;
}

static void
vips_foreign_load_magick7_error( VipsForeignLoadMagick7 *magick7 )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( magick7 );

	vips_error( class->nickname, _( "Magick: %s %s" ),
		magick7->exception->reason, 
		magick7->exception->description );
}

static int
vips_foreign_load_magick7_parse( VipsForeignLoadMagick7 *magick7, 
	Image *image, VipsImage *out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( magick7 );

	const char *key;
	int i;

#ifdef DEBUG
	printf( "image->depth = %zd\n", image->depth ); 
	printf( "GetImageType() = %d\n", GetImageType( image ) );
	vips_magick7_print_image_type( image ); 
	printf( "GetPixelChannels() = %zd\n", GetPixelChannels( image ) ); 
	printf( "image->columns = %zd\n", image->columns ); 
	printf( "image->rows = %zd\n", image->rows ); 
#endif /*DEBUG*/

	/* Ysize updated below once we have worked out how many frames to load.
	 */
	out->Xsize = image->columns;
	out->Ysize = image->rows;
	magick7->frame_height = image->rows;

	/* We skip all index channels. Lots of images can have these, it's not
	 * just the palette ones.
	 */
	out->Bands = 0;
	for( i = 0; i < GetPixelChannels( image ); i++ ) { 
		PixelChannel channel = GetPixelChannelChannel( image, i ); 
		
		if( channel != IndexPixelChannel ) 
			out->Bands += 1;
	} 

	/* Depth can be 'fractional'. You'd think we should use
	 * GetImageDepth() but that seems to compute something very complex. 
	 */
	out->BandFmt = -1;
	if( image->depth >= 1 && image->depth <= 8 ) 
		out->BandFmt = VIPS_FORMAT_UCHAR;
	if( image->depth >= 9 && image->depth <= 16 ) 
		out->BandFmt = VIPS_FORMAT_USHORT;
	if( image->depth == 32 )
		out->BandFmt = VIPS_FORMAT_FLOAT;
	if( image->depth == 64 )
		out->BandFmt = VIPS_FORMAT_DOUBLE;

	if( out->BandFmt == -1 ) {
		vips_error( class->nickname, 
			_( "unsupported bit depth %zd" ), image->depth );
		return( -1 );
	}

	switch( image->colorspace ) {
	case GRAYColorspace:
		if( out->BandFmt == VIPS_FORMAT_USHORT )
			out->Type = VIPS_INTERPRETATION_GREY16;
		else
			out->Type = VIPS_INTERPRETATION_B_W;
		break;

	case RGBColorspace:
		if( out->BandFmt == VIPS_FORMAT_USHORT )
			out->Type = VIPS_INTERPRETATION_RGB16;
		else
			out->Type = VIPS_INTERPRETATION_RGB;
		break;

	case sRGBColorspace:
		if( out->BandFmt == VIPS_FORMAT_USHORT )
			out->Type = VIPS_INTERPRETATION_RGB16;
		else
			out->Type = VIPS_INTERPRETATION_sRGB;
		break;

	case CMYKColorspace:
		out->Type = VIPS_INTERPRETATION_CMYK;
		break;

	default:
		vips_error( class->nickname, 
			_( "unsupported colorspace %d" ), 
			(int) image->colorspace );
		return( -1 );
	}

	switch( image->units ) {
	case PixelsPerInchResolution:
		out->Xres = image->resolution.x / 25.4;
		out->Yres = image->resolution.y / 25.4;
		vips_image_set_string( out, VIPS_META_RESOLUTION_UNIT, "in" );
		break;

	case PixelsPerCentimeterResolution:
		out->Xres = image->resolution.x / 10.0;
		out->Yres = image->resolution.y / 10.0;
		vips_image_set_string( out, VIPS_META_RESOLUTION_UNIT, "cm" );
		break;

	default:
		/* Things like GIF have no resolution info.
		 */
		out->Xres = 1.0;
		out->Yres = 1.0;
		break;
	}

	/* Other fields.
	 */
	out->Coding = VIPS_CODING_NONE;

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

	/* Get all the metadata.
	 */
	ResetImagePropertyIterator( image );
	while( (key = GetNextImageProperty( image )) ) {
		char name_text[256];
		VipsBuf name = VIPS_BUF_STATIC( name_text );
		const char *value;

		value = GetImageProperty( image, key, magick7->exception );
		if( !value ) {
			vips_foreign_load_magick7_error( magick7 );
			return( -1 ); 
		}
		vips_buf_appendf( &name, "magick-%s", key );
		vips_image_set_string( out, vips_buf_all( &name ), value );
	}

	/* Do we have a set of equal-sized frames? Append them.

	   	FIXME ... there must be an attribute somewhere from dicom read 
		which says this is a volumetric image

	 */
	magick7->n_frames = GetImageListLength( GetFirstImageInList( image ) );

#ifdef DEBUG
	printf( "image has %d frames\n", magick7->n_frames );
#endif /*DEBUG*/

	if( magick7->n != -1 )
		magick7->n_frames = VIPS_MIN( magick7->n_frames, magick7->n );

	/* So we can finally set the height.
	 */
	if( magick7->n_frames > 1 ) {
		vips_image_set_int( out, VIPS_META_PAGE_HEIGHT, out->Ysize );
		out->Ysize *= magick7->n_frames;
	}

	return( 0 );
}

/* We don't bother with GetPixelReadMask((), assume it's everywhere. Don't
 * bother with traits, assume taht's always update.
 *
 * We do skip index channels. Palette images add extra index channels
 * containing the index value from the file before colourmap lookup.
 */
#define UNPACK( TYPE ) { \
	TYPE * restrict tq = (TYPE *) q; \
	int x; \
	int b; \
	\
	for( x = 0; x < r->width; x++ ) { \
		for( b = 0; b < GetPixelChannels( image ); b++ ) { \
			PixelChannel channel = \
				GetPixelChannelChannel( image, b ); \
			\
			if( channel != IndexPixelChannel ) \
				*tq++ = p[b]; \
		} \
		\
		p += GetPixelChannels( image ); \
	} \
}

static int
vips_foreign_load_magick7_fill_region( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) a;
	VipsRect *r = &or->valid;
	VipsImage *im = or->im;

	int y;

	for( y = 0; y < r->height; y++ ) {
		int top = r->top + y;
		int frame = top / magick7->frame_height;
		int line = top % magick7->frame_height;
		Image *image = magick7->frames[frame];

		Quantum * restrict p;
		VipsPel * restrict q;

		g_mutex_lock( magick7->lock );
		p = GetCacheViewAuthenticPixels( magick7->cache_view[frame],
			r->left, line, r->width, 1, 
			magick7->exception );
		g_mutex_unlock( magick7->lock );

		if( !p ) 
			/* This can happen if, for example, some frames of a
			 * gif are shorter than others. It's not always
			 * an error.
			 */
			continue;

		q = VIPS_REGION_ADDR( or, r->left, top ); 

		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			UNPACK( unsigned char ); 
			break;

		case VIPS_FORMAT_USHORT:
			UNPACK( unsigned short ); 
			break;

		case VIPS_FORMAT_FLOAT:
			UNPACK( float ); 
			break;

		case VIPS_FORMAT_DOUBLE:
			UNPACK( double ); 
			break;

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

static int
vips_foreign_load_magick7_load( VipsForeignLoadMagick7 *magick7 )
{
	VipsForeignLoad *load = (VipsForeignLoad *) magick7;

	Image *p;
	int i;

#ifdef DEBUG
	printf( "vips_foreign_load_magick7_load: %p\n", magick7 ); 
#endif /*DEBUG*/

	if( vips_foreign_load_magick7_parse( magick7, 
		magick7->image, load->out ) )
		return( -1 );

	/* Record frame pointers.
	 */
	g_assert( !magick7->frames ); 
	if( !(magick7->frames = VIPS_ARRAY( NULL, magick7->n_frames, Image * )) )
		return( -1 );
	p = magick7->image;
	for( i = 0; i < magick7->n_frames; i++ ) {
		magick7->frames[i] = p;
		p = GetNextImageInList( p );
	}

	/* And a cache_view for each frame.
	 */
	g_assert( !magick7->cache_view ); 
	if( !(magick7->cache_view = VIPS_ARRAY( NULL, 
		magick7->n_frames, CacheView * )) )
		return( -1 );
	for( i = 0; i < magick7->n_frames; i++ ) {
		magick7->cache_view[i] = AcquireAuthenticCacheView( 
			magick7->frames[i], magick7->exception );
	}

#ifdef DEBUG
	/* Only display the traits from frame0, they should all be the same.
	 */
	vips_magick7_print_traits( magick7->frames[0] ); 
	vips_magick7_print_channel_names( magick7->frames[0] );
#endif /*DEBUG*/

	if( vips_image_generate( load->out, 
		NULL, vips_foreign_load_magick7_fill_region, NULL, 
		magick7, NULL ) )
		return( -1 );

	return( 0 );
}

typedef struct _VipsForeignLoadMagick7File {
	VipsForeignLoadMagick7 parent_object;

	char *filename; 

} VipsForeignLoadMagick7File;

typedef VipsForeignLoadMagick7Class VipsForeignLoadMagick7FileClass;

G_DEFINE_TYPE( VipsForeignLoadMagick7File, vips_foreign_load_magick7_file, 
	vips_foreign_load_magick7_get_type() );

static gboolean
ismagick7( const char *filename )
{
	Image *image;
	ImageInfo *image_info;
	ExceptionInfo *exception;
	int result;

	vips_foreign_load_magick7_genesis();

	/* Horribly slow :-(
	 */
	image_info = CloneImageInfo( NULL );
	exception = AcquireExceptionInfo();
	vips_strncpy( image_info->filename, filename, MagickPathExtent );
	image = PingImage( image_info, exception );
	result = image != NULL;
	VIPS_FREEF( DestroyImageList, image );
	VIPS_FREEF( DestroyImageInfo, image_info ); 
	VIPS_FREEF( DestroyExceptionInfo, exception ); 

	return( result );
}

static int
vips_foreign_load_magick7_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) load;
	VipsForeignLoadMagick7File *file = (VipsForeignLoadMagick7File *) load;

#ifdef DEBUG
	printf( "vips_foreign_load_magick7_file_header: %p\n", load ); 
#endif /*DEBUG*/

	vips_strncpy( magick7->image_info->filename, file->filename, 
		MagickPathExtent );

	/* It would be great if we could PingImage and just read the header,
	 * but sadly many IM coders do not support ping. The critical one for
	 * us is DICOM.
	 * 
	 * We have to read the whole image in _header.
	 */
	magick7->image = ReadImage( magick7->image_info, magick7->exception );
	if( !magick7->image ) {
		vips_foreign_load_magick7_error( magick7 ); 
		return( -1 );
	}

	if( vips_foreign_load_magick7_load( magick7 ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

static void
vips_foreign_load_magick7_file_class_init( 
	VipsForeignLoadMagick7FileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload";
	object_class->description = _( "load file with ImageMagick7" );

	load_class->is_a = ismagick7;
	load_class->header = vips_foreign_load_magick7_file_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagick7File, filename ),
		NULL );

}

static void
vips_foreign_load_magick7_file_init( VipsForeignLoadMagick7File *magick7_file )
{
}

typedef struct _VipsForeignLoadMagick7Buffer {
	VipsForeignLoadMagick7 parent_object;

	VipsArea *buf;

} VipsForeignLoadMagick7Buffer;

typedef VipsForeignLoadMagick7Class VipsForeignLoadMagick7BufferClass;

G_DEFINE_TYPE( VipsForeignLoadMagick7Buffer, vips_foreign_load_magick7_buffer, 
	vips_foreign_load_magick7_get_type() );

static gboolean
vips_foreign_load_magick7_buffer_is_a_buffer( const void *buf, size_t len )
{
	Image *image;
	ImageInfo *image_info;
	ExceptionInfo *exception;
	int result;

	vips_foreign_load_magick7_genesis();

	/* Horribly slow :-(
	 */
	image_info = CloneImageInfo( NULL );
	exception = AcquireExceptionInfo();
	image = PingBlob( image_info, buf, len, exception );
	result = image != NULL;
	VIPS_FREEF( DestroyImageList, image );
	VIPS_FREEF( DestroyImageInfo, image_info ); 
	VIPS_FREEF( DestroyExceptionInfo, exception ); 

	return( result );
}

static int
vips_foreign_load_magick7_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) load;
	VipsForeignLoadMagick7Buffer *magick7_buffer = 
		(VipsForeignLoadMagick7Buffer *) load;

#ifdef DEBUG
	printf( "vips_foreign_load_magick7_buffer_header: %p\n", load ); 
#endif /*DEBUG*/

	/* It would be great if we could PingBlob and just read the header,
	 * but sadly many IM coders do not support ping. The critical one for
	 * us is DICOM.
	 * 
	 * We have to read the whole image in _header.
	 */
	magick7->image = BlobToImage( magick7->image_info, 
		magick7_buffer->buf->data, magick7_buffer->buf->length,
		magick7->exception );
	if( !magick7->image ) {
		vips_foreign_load_magick7_error( magick7 ); 
		return( -1 );
	}

	if( vips_foreign_load_magick7_load( magick7 ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_magick7_buffer_class_init( 
	VipsForeignLoadMagick7BufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_buffer";
	object_class->description = _( "load buffer with ImageMagick7" );

	load_class->is_a_buffer = vips_foreign_load_magick7_buffer_is_a_buffer;
	load_class->header = vips_foreign_load_magick7_buffer_header;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagick7Buffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_magick7_buffer_init( VipsForeignLoadMagick7Buffer *buffer )
{
}

#endif /*HAVE_MAGICK7*/
