/* make a thumbnail ... wraps up the process of thumbnailing, including
 * premultiply, colour management etc etc
 *
 * 2/11/16
 * 	- from vipsthumbnail.c
 * 6/1/17
 * 	- add @size parameter
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#define VIPS_TYPE_THUMBNAIL (vips_thumbnail_get_type())
#define VIPS_THUMBNAIL( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_THUMBNAIL, VipsThumbnail ))
#define VIPS_THUMBNAIL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_THUMBNAIL, VipsThumbnailClass))
#define VIPS_IS_THUMBNAIL( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_THUMBNAIL ))
#define VIPS_IS_THUMBNAIL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_THUMBNAIL ))
#define VIPS_THUMBNAIL_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_THUMBNAIL, VipsThumbnailClass ))

typedef struct _VipsThumbnail {
	VipsOperation parent_instance;

	VipsImage *out;
	int width;
	int height;
	VipsSize size;

	gboolean auto_rotate;
	gboolean crop;
	gboolean linear;
	char *export_profile;
	char *import_profile;

	/* Set by subclasses to the input image.
	 */
	VipsImage *in;

	/* Bits of info we read from the input image when we get the header of
	 * the original.
	 */
	const char *loader;		/* Eg. "jpegload_buffer" */
	int input_width;
	int input_height;
	VipsAngle angle; 		/* From vips_autorot_get_angle() */

} VipsThumbnail;

typedef struct _VipsThumbnailClass {
	VipsOperationClass parent_class;

	/* Fill out the info section of VipsThumbnail from the input object.
	 */
	int (*get_info)( VipsThumbnail *thumbnail );  

	/* Open, giving either a scale or a shrink. @shrink is an integer shrink
	 * factor suitable for vips_jpegload() or equivalent, @scale is a
	 * double scale factor, suitable for vips_svgload() or similar.
	 */
	VipsImage *(*open)( VipsThumbnail *thumbnail, int shrink, double scale );

} VipsThumbnailClass;

G_DEFINE_ABSTRACT_TYPE( VipsThumbnail, vips_thumbnail, VIPS_TYPE_OPERATION );

static void
vips_thumbnail_dispose( GObject *gobject )
{
#ifdef DEBUG
	printf( "vips_thumbnail_dispose: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	G_OBJECT_CLASS( vips_thumbnail_parent_class )->dispose( gobject );
}

static void
vips_thumbnail_finalize( GObject *gobject )
{
#ifdef DEBUG
	printf( "vips_thumbnail_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	G_OBJECT_CLASS( vips_thumbnail_parent_class )->finalize( gobject );
}

/* Calculate the shrink factor, taking into account auto-rotate, the fit mode,
 * and so on.
 */
static double
vips_thumbnail_calculate_shrink( VipsThumbnail *thumbnail, 
	int input_width, int input_height )
{
	gboolean rotate = 
		thumbnail->angle == VIPS_ANGLE_D90 || 
		thumbnail->angle == VIPS_ANGLE_D270;
	int width = thumbnail->auto_rotate && rotate ? 
		input_height : input_width;
	int height = thumbnail->auto_rotate && rotate ? 
		input_width : input_height;

	VipsDirection direction;
	double shrink;

	/* Calculate the horizontal and vertical shrink we'd need to fit the
	 * image to the bounding box, and pick the biggest. 
	 *
	 * In crop mode, we aim to fill the bounding box, so we must use the
	 * smaller axis.
	 */
	double horizontal = (double) width / thumbnail->width;
	double vertical = (double) height / thumbnail->height;

	if( thumbnail->crop ) {
		if( horizontal < vertical )
			direction = VIPS_DIRECTION_HORIZONTAL;
		else
			direction = VIPS_DIRECTION_VERTICAL;
	}
	else {
		if( horizontal < vertical )
			direction = VIPS_DIRECTION_VERTICAL;
		else
			direction = VIPS_DIRECTION_HORIZONTAL;
	}

	shrink = direction == VIPS_DIRECTION_HORIZONTAL ?
		horizontal : vertical;  

	/* Restrict to only upsize, only downsize, or both.
	 */
	if( thumbnail->size == VIPS_SIZE_UP )
		shrink = VIPS_MIN( 1, shrink );
	if( thumbnail->size == VIPS_SIZE_DOWN )
		shrink = VIPS_MAX( 1, shrink );

	return( shrink ); 
}

/* Find the best jpeg preload shrink.
 */
static int
vips_thumbnail_find_jpegshrink( VipsThumbnail *thumbnail, int width, int height )
{
	double shrink = 
		vips_thumbnail_calculate_shrink( thumbnail, width, height ); 

	/* We can't use pre-shrunk images in linear mode. libjpeg shrinks in Y
	 * (of YCbCR), not linear space.
	 */
	if( thumbnail->linear )
		return( 1 ); 

	/* Shrink-on-load is a simple block shrink and will add quite a bit of
	 * extra sharpness to the image. We want to block shrink to a
	 * bit above our target, then vips_resize() to the final size. 
	 *
	 * Leave at least a factor of two for the final resize step.
	 */
	if( shrink >= 16 )
		return( 8 );
	else if( shrink >= 8 )
		return( 4 );
	else if( shrink >= 4 )
		return( 2 );
	else 
		return( 1 );
}

/* Open the image, returning the best version for thumbnailing. 
 *
 * For example, libjpeg supports fast shrink-on-read, so if we have a JPEG, 
 * we can ask VIPS to load a lower resolution version.
 */
static VipsImage *
vips_thumbnail_open( VipsThumbnail *thumbnail )
{
	VipsThumbnailClass *class = VIPS_THUMBNAIL_GET_CLASS( thumbnail );

	VipsImage *im;
	int shrink;
	double scale;

	if( class->get_info( thumbnail ) )
		return( NULL );
	g_info( "selected loader is %s", thumbnail->loader ); 
	g_info( "input size is %d x %d", 
		thumbnail->input_width, thumbnail->input_height ); 

	shrink = 1;
	scale = 1.0;

	if( vips_isprefix( "VipsForeignLoadJpeg", thumbnail->loader ) ) {
		shrink = vips_thumbnail_find_jpegshrink( thumbnail, 
			thumbnail->input_width, thumbnail->input_height );
		g_info( "loading jpeg with factor %d pre-shrink", shrink ); 
	}
	else if( vips_isprefix( "VipsForeignLoadPdf", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", thumbnail->loader ) ) {
		scale = 1.0 / vips_thumbnail_calculate_shrink( thumbnail, 
			thumbnail->input_width, thumbnail->input_height ); 
		g_info( "loading PDF/SVG with factor %g pre-scale", scale ); 
	}
	else if( vips_isprefix( "VipsForeignLoadWebp", thumbnail->loader ) ) {
		shrink = vips_thumbnail_calculate_shrink( thumbnail, 
			thumbnail->input_width, thumbnail->input_height ); 
		g_info( "loading webp with factor %d pre-shrink", shrink ); 
	}

	if( !(im = class->open( thumbnail, shrink, scale )) )
		return( NULL );

	return( im ); 
}

static int
vips_thumbnail_build( VipsObject *object )
{
	VipsThumbnail *thumbnail = VIPS_THUMBNAIL( object );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 12 );
	VipsInterpretation interpretation = thumbnail->linear ?
		VIPS_INTERPRETATION_scRGB : VIPS_INTERPRETATION_sRGB; 

	VipsImage *in;
	double shrink;

	/* TRUE if we've done the import of an ICC transform and still need to
	 * export.
	 */
	gboolean have_imported;

	/* TRUE if we've premultiplied and need to unpremultiply.
	 */
	gboolean have_premultiplied;
	VipsBandFormat unpremultiplied_format;

#ifdef DEBUG
	printf( "vips_thumbnail_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_thumbnail_parent_class )->build( object ) )
		return( -1 );

	if( !vips_object_argument_isset( object, "height" ) )
		thumbnail->height = thumbnail->width;

	if( !(t[0] = vips_thumbnail_open( thumbnail )) )
		return( -1 );
	in = t[0];

	/* RAD needs special unpacking.
	 */
	if( in->Coding == VIPS_CODING_RAD ) {
		g_info( "unpacking Rad to float" );

		/* rad is scrgb.
		 */
		if( vips_rad2float( in, &t[0], NULL ) )
			return( -1 );
		in = t[0];
	}

	/* In linear mode, we import right at the start. 
	 *
	 * We also have to import the whole image if it's CMYK, since
	 * vips_colourspace() (see below) doesn't know about CMYK.
	 *
	 * This is only going to work for images in device space. If you have
	 * an image in PCS which also has an attached profile, strange things
	 * will happen. 
	 */
	have_imported = FALSE;
	if( (thumbnail->linear ||
		in->Type == VIPS_INTERPRETATION_CMYK) &&
		in->Coding == VIPS_CODING_NONE &&
		(in->BandFmt == VIPS_FORMAT_UCHAR ||
		 in->BandFmt == VIPS_FORMAT_USHORT) &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 thumbnail->import_profile) ) {
		if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) )
			g_info( "importing with embedded profile" );
		else
			g_info( "importing with profile %s", 
				thumbnail->import_profile );

		if( vips_icc_import( in, &t[1], 
			"input_profile", thumbnail->import_profile,
			"embedded", TRUE,
			"pcs", VIPS_PCS_XYZ,
			NULL ) )  
			return( -1 );

		in = t[1];

		have_imported = TRUE;
	}

	/* To the processing colourspace. This will unpack LABQ as well.
	 */
	g_info( "converting to processing space %s",
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, interpretation ) ); 
	if( vips_colourspace( in, &t[2], interpretation, NULL ) ) 
		return( -1 ); 
	in = t[2];

	/* If there's an alpha, we have to premultiply before shrinking. See
	 * https://github.com/jcupitt/libvips/issues/291
	 */
	have_premultiplied = FALSE;
	if( vips_image_hasalpha( in ) ) { 
		g_info( "premultiplying alpha" ); 
		if( vips_premultiply( in, &t[3], NULL ) ) 
			return( -1 );
		have_premultiplied = TRUE;

		/* vips_premultiply() makes a float image. When we
		 * vips_unpremultiply() below, we need to cast back to the
		 * pre-premultiply format.
		 */
		unpremultiplied_format = in->BandFmt;
		in = t[3];
	}

	shrink = vips_thumbnail_calculate_shrink( thumbnail, 
		in->Xsize, in->Ysize );

	/* Use centre convention to better match imagemagick.
	 */
	if( vips_resize( in, &t[4], 1.0 / shrink, 
		"centre", TRUE, 
		NULL ) ) 
		return( -1 );
	in = t[4];

	if( have_premultiplied ) {
		g_info( "unpremultiplying alpha" ); 
		if( vips_unpremultiply( in, &t[5], NULL ) || 
			vips_cast( t[5], &t[6], unpremultiplied_format, NULL ) )
			return( -1 );
		in = t[6];
	}

	/* Colour management.
	 *
	 * If we've already imported, just export. Otherwise, we're in 
	 * device space and we need a combined import/export to transform to 
	 * the target space.
	 */
	if( have_imported ) { 
		if( thumbnail->export_profile ||
			vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
			g_info( "exporting to device space with a profile" );
			if( vips_icc_export( in, &t[7], 
				"output_profile", thumbnail->export_profile,
				NULL ) )  
				return( -1 );
			in = t[7];
		}
		else {
			g_info( "converting to sRGB" );
			if( vips_colourspace( in, &t[7], 
				VIPS_INTERPRETATION_sRGB, NULL ) ) 
				return( -1 ); 
			in = t[7];
		}
	}
	else if( thumbnail->export_profile &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 thumbnail->import_profile) ) {
		VipsImage *out;

		g_info( "exporting with profile %s", thumbnail->export_profile );

		/* We first try with the embedded profile, if any, then if
		 * that fails try again with the supplied fallback profile.
		 */
		out = NULL; 
		if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
			g_info( "importing with embedded profile" );

			if( vips_icc_transform( in, &t[7], 
				thumbnail->export_profile,
				"embedded", TRUE,
				NULL ) ) {
				g_warning( _( "unable to import with "
						"embedded profile: %s" ),
					vips_error_buffer() );

				vips_error_clear();
			}
			else
				out = t[7];
		}

		if( !out &&
			thumbnail->import_profile ) { 
			g_info( "importing with fallback profile" );

			if( vips_icc_transform( in, &t[7], 
				thumbnail->export_profile,
				"input_profile", thumbnail->import_profile,
				"embedded", FALSE,
				NULL ) )  
				return( -1 );

			out = t[7];
		}

		/* If the embedded profile failed and there's no fallback or
		 * the fallback failed, out will still be NULL.
		 */
		if( out )
			in = out;
	}

	if( thumbnail->crop ) {
		int left = (in->Xsize - thumbnail->width) / 2;
		int top = (in->Ysize - thumbnail->height) / 2;

		g_info( "cropping to %dx%d",
			thumbnail->width, thumbnail->height ); 
		if( vips_extract_area( in, &t[8], left, top, 
			thumbnail->width, thumbnail->height, NULL ) )
			return( -1 ); 
		in = t[8];
	}

	if( thumbnail->auto_rotate &&
		thumbnail->angle != VIPS_ANGLE_D0 ) {
		VipsAngle angle = vips_autorot_get_angle( in );

		g_info( "rotating by %s", 
			vips_enum_nick( VIPS_TYPE_ANGLE, angle ) ); 

		/* Need to copy to memory, we have to stay seq.
		 */
		if( !(t[9] = vips_image_copy_memory( in )) ||
			vips_rot( t[9], &t[10], angle, NULL ) )
			return( -1 ); 
		in = t[10];

		vips_autorot_remove_angle( in );
	}

	g_object_set( thumbnail, "out", vips_image_new(), NULL ); 

	if( vips_image_write( in, thumbnail->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_thumbnail_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_thumbnail_dispose;
	gobject_class->finalize = vips_thumbnail_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail_base";
	vobject_class->description = _( "thumbnail generation" );
	vobject_class->build = vips_thumbnail_build;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsThumbnail, out ) );

	VIPS_ARG_INT( class, "width", 3, 
		_( "Target width" ), 
		_( "Size to this width" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 113, 
		_( "Target height" ), 
		_( "Size to this height" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, height ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_ENUM( class, "size", 114, 
		_( "size" ), 
		_( "Only upsize, only downsize, or both" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, size ),
		VIPS_TYPE_SIZE, VIPS_SIZE_BOTH ); 

	VIPS_ARG_BOOL( class, "auto_rotate", 115, 
		_( "Auto rotate" ), 
		_( "Use orientation tags to rotate image upright" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, auto_rotate ),
		TRUE ); 

	VIPS_ARG_BOOL( class, "crop", 116, 
		_( "Crop" ), 
		_( "Reduce to fill target rectangle, then crop" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, crop ),
		FALSE ); 

	VIPS_ARG_BOOL( class, "linear", 117, 
		_( "Linear" ), 
		_( "Reduce in linear light" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, linear ),
		FALSE ); 

	VIPS_ARG_STRING( class, "import_profile", 118, 
		_( "Import profile" ), 
		_( "Fallback import profile" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, import_profile ),
		NULL ); 

	VIPS_ARG_STRING( class, "export_profile", 119, 
		_( "Export profile" ), 
		_( "Fallback export profile" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, export_profile ),
		NULL ); 

}

static void
vips_thumbnail_init( VipsThumbnail *thumbnail )
{
	thumbnail->width = 1;
	thumbnail->height = 1;
	thumbnail->auto_rotate = TRUE;
}

typedef struct _VipsThumbnailFile {
	VipsThumbnail parent_object;

	char *filename; 
} VipsThumbnailFile;

typedef VipsThumbnailClass VipsThumbnailFileClass;

G_DEFINE_TYPE( VipsThumbnailFile, vips_thumbnail_file, 
	vips_thumbnail_get_type() );

/* Get the info from a file.
 */
static int
vips_thumbnail_file_get_info( VipsThumbnail *thumbnail )
{
	VipsThumbnailFile *file = (VipsThumbnailFile *) thumbnail;

	VipsImage *image;

	g_info( "thumbnailing %s", file->filename ); 

	if( !(thumbnail->loader = vips_foreign_find_load( file->filename )) ||
		!(image = vips_image_new_from_file( file->filename, NULL )) )
		return( -1 );

	thumbnail->input_width = image->Xsize;
	thumbnail->input_height = image->Ysize;
	thumbnail->angle = vips_autorot_get_angle( image );

	g_object_unref( image );

	return( 0 );
}

/* Open an image, pre-shrinking as appropriate. Some formats use shrink, some
 * scale, never both. 
 */
static VipsImage *
vips_thumbnail_file_open( VipsThumbnail *thumbnail, int shrink, double scale )
{
	VipsThumbnailFile *file = (VipsThumbnailFile *) thumbnail;

	if( shrink != 1 ) 
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", shrink,
			NULL ) );
	else if( scale != 1.0 )
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", scale,
			NULL ) );
	else
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) );
}

static void
vips_thumbnail_file_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsThumbnailClass *thumbnail_class = VIPS_THUMBNAIL_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail";
	vobject_class->description = _( "generate thumbnail from file" );

	thumbnail_class->get_info = vips_thumbnail_file_get_info;
	thumbnail_class->open = vips_thumbnail_file_open;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to read from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsThumbnailFile, filename ),
		NULL );

}

static void
vips_thumbnail_file_init( VipsThumbnailFile *file )
{
}

/**
 * vips_thumbnail:
 * @filename: file to read from
 * @out: output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize or both
 * * @auto_rotate: %gboolean, rotate upright using orientation tag
 * * @crop: %gboolean, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_profile: %gchararray, fallback import ICC profile
 * * @export_profile: %gchararray, export ICC profile
 *
 * Make a thumbnail from a file. Shrinking is done in three stages: using any
 * shrink-on-load features available in the file import library, using a block
 * shrink, and using a lanczos3 shrink. At least the final 200% is done with
 * lanczos3. The output should be high quality, and the operation should be
 * quick. 
 *
 * See vips_thumbnail_buffer() to thumbnail from a memory source. 
 *
 * The output image will fit within a square of size @width x @width. You can
 * specify a separate height with the @height option. 
 *
 * If you set @crop, then the output image will fill the whole of the @width x
 * @height rectangle, with any excess cropped away.
 *
 * Normally the operation will upsize or downsize as required. If @size is set
 * to #VIPS_SIZE_UP, the operation will only upsize and will just
 * copy if asked to downsize. 
 * If @size is set
 * to #VIPS_SIZE_DOWN, the operation will only downsize and will just
 * copy if asked to upsize. 
 *
 * Normally any orientation tags on the input image (such as EXIF tags) are
 * interpreted to rotate the image upright. If you set @auto_rotate to %FALSE,
 * these tags will not be interpreted.
 *
 * Shrinking is normally done in sRGB colourspace. Set @linear to shrink in 
 * linear light colourspace instead --- this can give better results, but can
 * also be far slower, since tricks like JPEG shrink-on-load cannot be used in
 * linear space.
 *
 * If you set @export_profile to the filename of an ICC profile, the image 
 * will be transformed to the target colourspace before writing to the 
 * output. You can also give an @import_profile which will be used if the 
 * input image has no ICC profile, or if the profile embedded in the 
 * input image is broken.
 *
 * See also: vips_thumbnail_buffer().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thumbnail( const char *filename, VipsImage **out, int width, ... )
{
	va_list ap;
	int result;

	va_start( ap, width );
	result = vips_call_split( "thumbnail", ap, filename, out, width );
	va_end( ap );

	return( result );
}

typedef struct _VipsThumbnailBuffer {
	VipsThumbnail parent_object;

	VipsArea *buf;
} VipsThumbnailBuffer;

typedef VipsThumbnailClass VipsThumbnailBufferClass;

G_DEFINE_TYPE( VipsThumbnailBuffer, vips_thumbnail_buffer, 
	vips_thumbnail_get_type() );

/* Get the info from a buffer.
 */
static int
vips_thumbnail_buffer_get_info( VipsThumbnail *thumbnail )
{
	VipsThumbnailBuffer *buffer = (VipsThumbnailBuffer *) thumbnail;

	VipsImage *image;

	g_info( "thumbnailing %zd bytes of data", buffer->buf->length ); 

	if( !(thumbnail->loader = vips_foreign_find_load_buffer( 
			buffer->buf->data, buffer->buf->length )) ||
		!(image = vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, "", NULL )) )
		return( -1 );

	thumbnail->input_width = image->Xsize;
	thumbnail->input_height = image->Ysize;
	thumbnail->angle = vips_autorot_get_angle( image );

	g_object_unref( image );

	return( 0 );
}

/* Open an image, pre-shrinking as appropriate. Some formats use shrink, some
 * scale, never both. 
 */
static VipsImage *
vips_thumbnail_buffer_open( VipsThumbnail *thumbnail, 
	int shrink, double scale )
{
	VipsThumbnailBuffer *buffer = (VipsThumbnailBuffer *) thumbnail;

	if( shrink != 1 ) 
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, "", 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", shrink,
			NULL ) );
	else if( scale != 1.0 )
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, "", 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", scale,
			NULL ) );
	else
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, "", 
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) );
}

static void
vips_thumbnail_buffer_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsThumbnailClass *thumbnail_class = VIPS_THUMBNAIL_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail_buffer";
	vobject_class->description = _( "generate thumbnail from buffer" );

	thumbnail_class->get_info = vips_thumbnail_buffer_get_info;
	thumbnail_class->open = vips_thumbnail_buffer_open;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsThumbnailBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_thumbnail_buffer_init( VipsThumbnailBuffer *buffer )
{
}

/**
 * vips_thumbnail_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize or both
 * * @auto_rotate: %gboolean, rotate upright using orientation tag
 * * @crop: %gboolean, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_probuffer: %gchararray, fallback import ICC probuffer
 * * @export_probuffer: %gchararray, export ICC probuffer
 *
 * Exacty as vips_thumbnail(), but read from a memory buffer. 
 *
 * See also: vips_thumbnail().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thumbnail_buffer( void *buf, size_t len, VipsImage **out, int width, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, width );
	result = vips_call_split( "thumbnail_buffer", ap, blob, out, width );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
