/* make a thumbnail ... wraps up the process of thumbnailing, including
 * premultiply, colour management etc etc
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

	/* Set by subclasses to the input image.
	 */
	VIpsImage *in;

} VipsThumbnail;

typedef struct _VipsThumbnailClass {
	VipsOperationClass parent_class;

	/* Fetch the size and format from the input object. The returned static
	 * string is something like "jpegload" or "jpegload_buffer".
	 */
	const char *(*get_info)( VipsThumbnail *thumbnail, 
		int *width, int *height );

	/* Open, giving either a scale or a shrink. @shrink is an integer shrink
	 * factor suitable for vips_jpegload() or equivalent, @scale is a
	 * double scale factor, suitable for vips_svgload() or similar.
	 */
	VipsImage *(*open)( VipsThumbnail *thumbnail, int shrink, double scale );

} VipsThumbnailClass;

G_DEFINE_ABSTRACT_TYPE( VipsThumbnail, vips_thumbnail, VIPS_TYPE_OPERATION );

/* Calculate the shrink factor, taking into account auto-rotate, the fit mode,
 * and so on.
 */
static double
vips_thumbnail_calculate_shrink( VipsThumbnail *thumbnail, 
	int width, int height )
{
	VipsAngle angle = vips_autorot_get_angle( im ); 
	gboolean rotate = angle == VIPS_ANGLE_D90 || angle == VIPS_ANGLE_D270;
	int width = rotate_image && rotate ? im->Ysize : im->Xsize;
	int height = rotate_image && rotate ? im->Xsize : im->Ysize;

	VipsDirection direction;

	/* Calculate the horizontal and vertical shrink we'd need to fit the
	 * image to the bounding box, and pick the biggest. 
	 *
	 * In crop mode, we aim to fill the bounding box, so we must use the
	 * smaller axis.
	 */
	double horizontal = (double) width / thumbnail_width;
	double vertical = (double) height / thumbnail_height;

	if( crop_image ) {
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

	return( direction == VIPS_DIRECTION_HORIZONTAL ?
		horizontal : vertical );  
}

/* Find the best jpeg preload shrink.
 */
static int
vips_thumbnail_find_jpegshrink( VipsThumbnail *thumbnail, int width, int height )
{
	double shrink = vips_thumbnail_calculate_shrink( width, height ); 

	/* We can't use pre-shrunk images in linear mode. libjpeg shrinks in Y
	 * (of YCbCR), not linear space.
	 */
	if( thumbnail->linear_processing )
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
 * FOr example, libjpeg supports fast shrink-on-read, so if we have a JPEG, 
 * we can ask VIPS to load a lower resolution version.
 */
static VipsImage *
vips_thumbnail_open( VipsThumbnail *thumbnail )
{
	VipsThumbnailClass *class = VIPS_THUMBNAIL_GET_CLASS( thumbnail );

	const char *loader;
	int width;
	int height;
	VipsImage *im;
	int shrink;
	double scale;

	if( !(loader = class->get_info( filename, &width, &height )) )
		return( NULL );

	vips_info( "vipsthumbnail", "selected loader is %s", loader ); 
	vips_info( "vipsthumbnail", "start size is %d x %d", width, height ); 

	shrknk = 1;
	scale = 1.0;

	if( vips_isprefix( "VipsForeignLoadJpeg", loader ) ) {
		shrink = vips_thumbnail_find_jpegshrink( width, height );
		vips_info( "vipsthumbnail", 
			"loading jpeg with factor %d pre-shrink", shrink ); 

	}
	else if( vips_isprefix( "VipsForeignLoadPdf", loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", loader ) ) {
		scale = 1.0 / vips_thumbnail_calculate_shrink( width, height ); 
		vips_info( "vipsthumbnail", 
			"loading PDF/SVG with factor %g pre-scale", scale ); 
	}
	else if( strcmp( loader, "VipsForeignLoadWebpFile" ) == 0 ) {
		shrink = vips_thumbnail_calculate_shrink( width, height ); 
		vips_info( "vipsthumbnail", 
			"loading webp with factor %d pre-shrink", shrink ); 
	}

	if( !(im = class->open( filename, shrink, scale )) )
		return( NULL );
	vips_object_local( thumbnail, im );

	return( im ); 
}

static int
vips_thumbnail_build( VipsObject *object )
{
	VipsThumbnail *thumbnail = VIPS_CONVERSION( object );

#ifdef DEBUG
	printf( "vips_thumbnail_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_thumbnail_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_thumbnail_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

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

	VIPS_ARG_INT( class, "width", 113, 
		_( "Target width" ), 
		_( "Size to this width" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, width ),
		1, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "height", 113, 
		_( "Target height" ), 
		_( "Size to this height" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, height ),
		1, VIPS_MAX_COORD, 0 );

}

static void
vips_thumbnail_init( VipsThumbnail *thumbnail )
{
}

typedef struct _VipsThumbnailFile {
	VipsThumbnail parent_object;

	char *filename; 
} VipsThumbnailFile;

typedef VipsThumbnailClass VipsThumbnailFileClass;

G_DEFINE_TYPE( VipsThumbnailFile, vips_thumbnail_file, 
	vips_thumbnail_get_type() );

/* Open an image, returning the best version of that image for thumbnailing. 
 *
 * libjpeg supports fast shrink-on-read, so if we have a JPEG, we can ask 
 * VIPS to load a lower resolution version.
 */
static VipsImage *
vips_thumbnail_file_open( VipsThumbnailFile *file, const char *filename )
{
	const char *loader;
	VipsImage *im;

	vips_info( "vipsthumbnail", "thumbnailing %s", filename );

	if( linear_processing )
		vips_info( "vipsthumbnail", "linear mode" ); 

	if( !(loader = vips_foreign_find_load( filename )) )
		return( NULL );

	vips_info( "vipsthumbnail", "selected loader is %s", loader ); 

	if( strcmp( loader, "VipsForeignLoadJpegFile" ) == 0 ) {
		int jpegshrink;

		/* This will just read in the header and is quick.
		 */
		if( !(im = vips_image_new_from_file( filename, NULL )) )
			return( NULL );

		jpegshrink = thumbnail_find_jpegshrink( im );

		g_object_unref( im );

		vips_info( "vipsthumbnail", 
			"loading jpeg with factor %d pre-shrink", 
			jpegshrink ); 

		/* We can't use UNBUFERRED safely on very-many-core systems.
		 */
		if( !(im = vips_image_new_from_file( filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", jpegshrink,
			NULL )) )
			return( NULL );
	}
	else if( strcmp( loader, "VipsForeignLoadPdfFile" ) == 0 ||
		strcmp( loader, "VipsForeignLoadSvgFile" ) == 0 ) {
		double shrink;

		/* This will just read in the header and is quick.
		 */
		if( !(im = vips_image_new_from_file( filename, NULL )) )
			return( NULL );

		shrink = calculate_shrink( im ); 

		g_object_unref( im );

		vips_info( "vipsthumbnail", 
			"loading PDF/SVG with factor %g pre-shrink", 
			shrink ); 

		/* We can't use UNBUFERRED safely on very-many-core systems.
		 */
		if( !(im = vips_image_new_from_file( filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", 1.0 / shrink,
			NULL )) )
			return( NULL );
	}
	else if( strcmp( loader, "VipsForeignLoadWebpFile" ) == 0 ) {
		double shrink;

		/* This will just read in the header and is quick.
		 */
		if( !(im = vips_image_new_from_file( filename, NULL )) )
			return( NULL );

		shrink = calculate_shrink( im ); 

		g_object_unref( im );

		vips_info( "vipsthumbnail", 
			"loading webp with factor %g pre-shrink", 
			shrink ); 

		/* We can't use UNBUFERRED safely on very-many-core systems.
		 */
		if( !(im = vips_image_new_from_file( filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", (int) shrink,
			NULL )) )
			return( NULL );
	}
	else {
		/* All other formats. We can't use UNBUFERRED safely on 
		 * very-many-core systems.
		 */
		if( !(im = vips_image_new_from_file( filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL )) )
			return( NULL );
	}

	vips_object_local( process, im );

	return( im ); 
}

static int
vips_thumbnail_file_build( VipsObject *object )
{
	VipsThumbnailFile *file = VIPS_CONVERSION( object );

#ifdef DEBUG
	printf( "vips_thumbnail_file_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( file->filename ) {
	}

	if( VIPS_OBJECT_CLASS( vips_thumbnail_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_thumbnail_file_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail";
	vobject_class->description = _( "generate thumbnail from file" );
	vobject_class->build = vips_thumbnail_file_build;

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
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: compression level
 * * @interlace: interlace image
 * * @profile: ICC profile to embed
 * * @filter: #VipsForeignPngFilter row filter flag(s)
 *
 * Make an image thumbnail from a file. 
 *
 * See also: vips_thumbnail_buffer().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thumbnail( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "thumbnail", ap, filename, out );
	va_end( ap );

	return( result );
}


