/* make a thumbnail ... wraps up the process of thumbnailing, including
 * premultiply, colour management etc etc
 *
 * 2/11/16
 * 	- from vipsthumbnail.c
 * 6/1/17
 * 	- add @size parameter
 * 4/5/17
 * 	- add FORCE
 * 29/5/17
 * 	- don't cache (thanks tomasc)
 * 30/8/17
 * 	- add intent option, thanks kleisauke
 * 31/10/18
 * 	- deprecate auto_rotate, add no_rotate
 * 	- implement shrink-on-load for openslide images
 * 16/11/18
 * 	- implement shrink-on-load for tiff pyramid 
 * 3/2/19 kleisauke
 * 	- add option_string param to thumbnail_buffer
 * 23/4/19
 * 	- don't force import CMYK, since colourspace knows about it now
 * 24/4/19
 * 	- support multi-page (animated) images
 * 27/8/19 kleisauke
 *	- prevent over-pre-shrink in thumbnail
 * 30/9/19
 * 	- smarter heif thumbnail selection
 * 12/10/19
 * 	- add thumbnail_source
 * 3/5/20 kleisauke
 *	- prevent reduction in the vertical axis when the height is omitted
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

/* Should be plenty.
 */
#define MAX_LEVELS (256)

typedef struct _VipsThumbnail {
	VipsOperation parent_instance;

	VipsImage *out;
	int width;
	int height;
	VipsSize size;

	gboolean auto_rotate;
	gboolean no_rotate;
	VipsInteresting crop;
	gboolean linear;
	char *export_profile;
	char *import_profile;
	VipsIntent intent;

	/* Bits of info we read from the input image when we get the header of
	 * the original.
	 */
	const char *loader;		/* Eg. "VipsForeignLoadJpeg*" */
	int input_width;
	int input_height;
	int page_height;
	VipsAngle angle; 		/* From vips_autorot_get_angle() */
	int n_pages;			/* Pages in file */
	int n_loaded_pages;		/* Pages we've loaded from file */

	/* For openslide, we need to read out the size of each level too.
	 *
	 * These are filled out for pyr tiffs as well.
	 */
	int level_count;
	int level_width[MAX_LEVELS];
	int level_height[MAX_LEVELS];

	/* For HEIF, try to fetch the size of the stored thumbnail.
	 */
	int heif_thumbnail_width;
	int heif_thumbnail_height;

} VipsThumbnail;

typedef struct _VipsThumbnailClass {
	VipsOperationClass parent_class;

	/* Fill out the info section of VipsThumbnail from the input object.
	 */
	int (*get_info)( VipsThumbnail *thumbnail );  

	/* Open with some kind of shrink or scale factor. Exactly what we pass 
	 * and to what param depends on the loader. It'll be an integer shrink
	 * factor for vips_jpegload(), a double scale factor for vips_svgload().
	 *
	 * See VipsThumbnail::loader
	 */
	VipsImage *(*open)( VipsThumbnail *thumbnail, double factor );

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

/* Fetch an int openslide field from metadata. These are all represented as
 * strings. Return the default value if there's any problem.
 */
static int
get_int( VipsImage *image, const char *field, int default_value )
{
	const char *str;

	if( vips_image_get_typeof( image, field ) &&
		!vips_image_get_string( image, field, &str ) ) 
		return( atoi( str ) );

	return( default_value );
}

static void
vips_thumbnail_read_header( VipsThumbnail *thumbnail, VipsImage *image )
{
	thumbnail->input_width = image->Xsize;
	thumbnail->input_height = image->Ysize;
	thumbnail->angle = vips_autorot_get_angle( image );
	thumbnail->page_height = vips_image_get_page_height( image );
	thumbnail->n_pages = vips_image_get_n_pages( image );

	/* VIPS_META_N_PAGES is the number of pages in the document, 
	 * not the number we've read out into this image. We calculate
	 * ourselves from page_height. 
	 *
	 * vips_image_get_page_height() has verified that Ysize is a simple
	 * multiple of page_height.
	 */
	thumbnail->n_loaded_pages = 
		thumbnail->input_height / thumbnail->page_height;

	/* For openslide, read out the level structure too.
	 */
	if( vips_isprefix( "VipsForeignLoadOpenslide", thumbnail->loader ) ) {
		int level_count;
		int level;

		level_count = get_int( image, "openslide.level-count", 1 );
		level_count = VIPS_CLIP( 1, level_count, MAX_LEVELS );
		thumbnail->level_count = level_count;

		for( level = 0; level < level_count; level++ ) {
			char name[256];

			vips_snprintf( name, 256, 
				"openslide.level[%d].width", level );
			thumbnail->level_width[level] =
				 get_int( image, name, 0 );
			vips_snprintf( name, 256, 
				"openslide.level[%d].height", level );
			thumbnail->level_height[level] =
				get_int( image, name, 0 );
		}
	}
}

/* This may not be a pyr tiff, so no error if we can't find the layers. 
 * We just look for two or more pages following roughly /2 shrinks.
 */
static void
vips_thumbnail_get_tiff_pyramid( VipsThumbnail *thumbnail ) 
{
	VipsThumbnailClass *class = VIPS_THUMBNAIL_GET_CLASS( thumbnail );
	int i;

	for( i = 0; i < thumbnail->n_pages; i++ ) {
		VipsImage *page;
		int level_width;
		int level_height;
		int expected_level_width;
		int expected_level_height;

		if( !(page = class->open( thumbnail, i )) )
			return;
		level_width = page->Xsize;
		level_height = page->Ysize;
		VIPS_UNREF( page );

		expected_level_width = thumbnail->input_width / (1 << i);
		expected_level_height = thumbnail->input_height / (1 << i);

		/* This won't be exact due to rounding etc.
		 */
		if( abs( level_width - expected_level_width ) > 5 ||
			level_width < 2 )
			return;
		if( abs( level_height - expected_level_height ) > 5 ||
			level_height < 2 )
			return;

		thumbnail->level_width[i] = level_width;
		thumbnail->level_height[i] = level_height;
	}

	/* Now set level_count. This signals that we've found a pyramid.
	 */
#ifdef DEBUG
	printf( "vips_thumbnail_get_tiff_pyramid: %d layer pyramid detected\n",
	     thumbnail->n_pages );
#endif /*DEBUG*/
	thumbnail->level_count = thumbnail->n_pages;
}

static int
vips_thumbnail_get_heif_thumb_info( VipsThumbnail *thumbnail ) 
{
	VipsThumbnailClass *class = VIPS_THUMBNAIL_GET_CLASS( thumbnail );

	VipsImage *thumb;

	if( !(thumb = class->open( thumbnail, 1 )) )
		return( -1 );

	if( thumb->Xsize < thumbnail->input_width ) {
		thumbnail->heif_thumbnail_width = thumb->Xsize;
		thumbnail->heif_thumbnail_height = thumb->Ysize;
	}

	VIPS_UNREF( thumb );

	return( 0 );
}

/* Calculate the shrink factor, taking into account auto-rotate, the fit mode,
 * and so on.
 *
 * The hshrink/vshrink are the amount to shrink the input image axes by in
 * order for the output axes (ie. after rotation) to match the required 
 * thumbnail->width, thumbnail->height and fit mode.
 */
static void
vips_thumbnail_calculate_shrink( VipsThumbnail *thumbnail, 
	int input_width, int input_height, double *hshrink, double *vshrink )
{
	/* If we will be rotating, swap the target width and height.
	 */
	gboolean rotate = 
		(thumbnail->angle == VIPS_ANGLE_D90 || 
		 thumbnail->angle == VIPS_ANGLE_D270) &&
		thumbnail->auto_rotate;
	int target_width = rotate ? 
		thumbnail->height : thumbnail->width;
	int target_height = rotate ? 
		thumbnail->width : thumbnail->height;

	VipsDirection direction;

	/* Calculate the horizontal and vertical shrink we'd need to fit the
	 * image to the bounding box, and pick the biggest. 
	 *
	 * In crop mode, we aim to fill the bounding box, so we must use the
	 * smaller axis.
	 */
	*hshrink = (double) input_width / target_width;
	*vshrink = (double) input_height / target_height;

	if( thumbnail->crop != VIPS_INTERESTING_NONE ) {
		if( *hshrink < *vshrink )
			direction = VIPS_DIRECTION_HORIZONTAL;
		else
			direction = VIPS_DIRECTION_VERTICAL;
	}
	else {
		if( *hshrink < *vshrink )
			direction = VIPS_DIRECTION_VERTICAL;
		else
			direction = VIPS_DIRECTION_HORIZONTAL;
	}

	if( thumbnail->size != VIPS_SIZE_FORCE ) {
		if( direction == VIPS_DIRECTION_HORIZONTAL )
			*vshrink = *hshrink;
		else
			*hshrink = *vshrink;
	}

	if( thumbnail->size == VIPS_SIZE_UP ) {
		*hshrink = VIPS_MIN( 1, *hshrink );
		*vshrink = VIPS_MIN( 1, *vshrink );
	}
	else if( thumbnail->size == VIPS_SIZE_DOWN ) {
		*hshrink = VIPS_MAX( 1, *hshrink );
		*vshrink = VIPS_MAX( 1, *vshrink );
	}
}

/* Just the common part of the shrink: the bit by which both axes must be
 * shrunk.
 */
static double
vips_thumbnail_calculate_common_shrink( VipsThumbnail *thumbnail, 
	int width, int height )
{
	double hshrink;
	double vshrink;
	double shrink;

	vips_thumbnail_calculate_shrink( thumbnail, width, height, 
		&hshrink, &vshrink ); 

	shrink = VIPS_MIN( hshrink, vshrink );

	/* We don't want to shrink so much that we send an axis to 0.
	 */
	shrink = VIPS_MIN( shrink, VIPS_MIN( width, height ) ); 

	return( shrink ); 
}

/* Find the best jpeg preload shrink.
 */
static int
vips_thumbnail_find_jpegshrink( VipsThumbnail *thumbnail, 
	int width, int height )
{
	double shrink = vips_thumbnail_calculate_common_shrink( thumbnail, 
		width, height ); 

	/* We can't use pre-shrunk images in linear mode. libjpeg shrinks in Y
	 * (of YCbCR), not linear space.
	 */
	if( thumbnail->linear )
		return( 1 ); 

	/* Shrink-on-load is a simple block shrink and will add quite a bit of
	 * extra sharpness to the image. We want to block shrink to a
	 * bit above our target, then vips_shrink() / vips_reduce() to the 
	 * final size. 
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

/* Find the best pyramid (openslide or tiff) level.
 */
static int
vips_thumbnail_find_pyrlevel( VipsThumbnail *thumbnail, 
	int width, int height )
{
	int level;

	g_assert( thumbnail->level_count > 0 );
	g_assert( thumbnail->level_count <= MAX_LEVELS );

	for( level = thumbnail->level_count - 1; level >= 0; level-- ) 
		if( vips_thumbnail_calculate_common_shrink( thumbnail, 
			thumbnail->level_width[level], 
			thumbnail->level_height[level] ) >= 1.0 ) 
			return( level );

	return( 0 );
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
	double factor;

	if( class->get_info( thumbnail ) )
		return( NULL );
	g_info( "selected loader is %s", thumbnail->loader ); 
	g_info( "input size is %d x %d", 
		thumbnail->input_width, thumbnail->input_height ); 

	/* For tiff, we need a separate ->open() for each page to
	 * get all the pyramid levels.
	 */
	if( vips_isprefix( "VipsForeignLoadTiff", thumbnail->loader ) ) 
		vips_thumbnail_get_tiff_pyramid( thumbnail );

	/* For heif, we need to fetch the thumbnail size, in case we can use
	 * that as the source.
	 */
	if( vips_isprefix( "VipsForeignLoadHeif", thumbnail->loader ) ) 
		vips_thumbnail_get_heif_thumb_info( thumbnail );

	/* We read the openslide level structure in
	 * vips_thumbnail_read_header().
	 */

	factor = 1.0;

	if( vips_isprefix( "VipsForeignLoadJpeg", thumbnail->loader ) ) 
		factor = vips_thumbnail_find_jpegshrink( thumbnail, 
			thumbnail->input_width, thumbnail->input_height );
	else if( vips_isprefix( "VipsForeignLoadTiff", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadOpenslide", 
		thumbnail->loader ) ) 
		factor = vips_thumbnail_find_pyrlevel( thumbnail, 
			thumbnail->input_width, thumbnail->input_height );
	else if( vips_isprefix( "VipsForeignLoadPdf", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadWebp", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", thumbnail->loader ) ) 
		factor = vips_thumbnail_calculate_common_shrink( thumbnail, 
			thumbnail->input_width, 
			thumbnail->page_height );
	else if( vips_isprefix( "VipsForeignLoadHeif", thumbnail->loader ) ) {
		/* 'factor' is a gboolean which enables thumbnail load instead
		 * of image load.
		 *
		 * Use the thumbnail if, by using it, we could get a factor >
		 * 1.0, ie. we would not need to expand the thumbnail. 
		 *
		 * Don't use >= since factor can be clipped to 1.0 under some
		 * resizing modes.
		 */
		double shrink_factor = vips_thumbnail_calculate_common_shrink( 
			thumbnail, 
			thumbnail->heif_thumbnail_width, 
			thumbnail->heif_thumbnail_height );

		factor = shrink_factor > 1.0 ? 1 : 0;
	}

	g_info( "loading with factor %g pre-shrink", factor ); 

	if( !(im = class->open( thumbnail, factor )) )
		return( NULL );

	g_info( "pre-shrunk size is %d x %d", im->Xsize, im->Ysize ); 

	return( im ); 
}

static int
vips_thumbnail_build( VipsObject *object )
{
	VipsThumbnail *thumbnail = VIPS_THUMBNAIL( object );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 15 );
	VipsInterpretation interpretation = thumbnail->linear ?
		VIPS_INTERPRETATION_scRGB : VIPS_INTERPRETATION_sRGB; 

	VipsImage *in;
	int preshrunk_page_height;
	double hshrink;
	double vshrink;

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

	/* We have to support both no_rotate and auto_rotate optional args,
	 * with no_rotate being the new and not-deprecated one.
	 *
	 * If the new no_rotate flag has been set, that value overrides
	 * auto_rotate.
	 */
	if( vips_object_argument_isset( object, "no_rotate" ) ) 
		thumbnail->auto_rotate = !thumbnail->no_rotate;

	/* Open and do any pre-shrinking.
	 */
	if( !(t[0] = vips_thumbnail_open( thumbnail )) )
		return( -1 );
	in = t[0];

	/* After pre-shrink, but before the main shrink stage.
	 */
	preshrunk_page_height = vips_image_get_page_height( in );

	/* RAD needs special unpacking.
	 */
	if( in->Coding == VIPS_CODING_RAD ) {
		g_info( "unpacking Rad to float" );

		/* rad is scrgb.
		 */
		if( vips_rad2float( in, &t[12], NULL ) )
			return( -1 );
		in = t[12];
	}

	/* In linear mode, we import right at the start. 
	 *
	 * We also have to import the whole image if it's CMYK, since
	 * vips_colourspace() (see below) doesn't let you specify the fallback
	 * profile.
	 *
	 * This is only going to work for images in device space. If you have
	 * an image in PCS which also has an attached profile, strange things
	 * will happen. 
	 */
	have_imported = FALSE;
	if( thumbnail->linear &&
		in->Coding == VIPS_CODING_NONE &&
		(in->BandFmt == VIPS_FORMAT_UCHAR ||
		 in->BandFmt == VIPS_FORMAT_USHORT) &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 thumbnail->import_profile) ) {
		g_info( "importing to XYZ PCS" );
		if( thumbnail->import_profile ) 
			g_info( "fallback input profile %s", 
				thumbnail->import_profile );

		if( vips_icc_import( in, &t[1], 
			"input_profile", thumbnail->import_profile,
			"embedded", TRUE,
			"intent", thumbnail->intent,
			"pcs", VIPS_PCS_XYZ,
			NULL ) )  
			return( -1 );

		in = t[1];

		have_imported = TRUE;
	}

	/* To the processing colourspace. This will unpack LABQ, import CMYK,
	 * etc.
	 *
	 * If this is a CMYK image, we need to set have_imported since we only
	 * want to export at the end.
	 */
	if( in->Type == VIPS_INTERPRETATION_CMYK )
		have_imported = TRUE;
	g_info( "converting to processing space %s",
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, interpretation ) ); 
	if( vips_colourspace( in, &t[2], interpretation, NULL ) ) 
		return( -1 ); 
	in = t[2];

	/* If there's an alpha, we have to premultiply before shrinking. See
	 * https://github.com/libvips/libvips/issues/291
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

	/* Shrink to preshrunk_page_height, so we work for multi-page images.
	 */
	vips_thumbnail_calculate_shrink( thumbnail, 
		in->Xsize, preshrunk_page_height, &hshrink, &vshrink );

	/* In toilet-roll mode, we must adjust vshrink so that we exactly hit
	 * page_height or we'll have pixels straddling page boundaries.
	 */
	if( in->Ysize > preshrunk_page_height ) {
		int target_page_height = VIPS_RINT( 
			preshrunk_page_height / vshrink );
		int target_image_height = target_page_height * 
			thumbnail->n_loaded_pages;

		vshrink = (double) in->Ysize / target_image_height;
	}

	if( vips_resize( in, &t[4], 1.0 / hshrink, 
		"vscale", 1.0 / vshrink, 
		NULL ) ) 
		return( -1 );
	in = t[4];

	/* Only set page-height if we have more than one page, or this could
	 * accidentally turn into an animated image later.
	 */
	if( thumbnail->n_loaded_pages > 1 ) {
		int output_page_height = 
			VIPS_RINT( preshrunk_page_height / vshrink );

		if( vips_copy( in, &t[13], NULL ) )
			return( -1 );
		in = t[13];

		vips_image_set_int( in, 
			VIPS_META_PAGE_HEIGHT, output_page_height );
	}

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
				"intent", thumbnail->intent,
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
		g_info( "transforming to %s", thumbnail->export_profile );
		if( thumbnail->import_profile ) 
			g_info( "fallback input profile %s", 
				thumbnail->import_profile );

		if( vips_icc_transform( in, &t[7], 
			thumbnail->export_profile,
			"input_profile", thumbnail->import_profile,
			"intent", thumbnail->intent,
			"embedded", TRUE,
			NULL ) ) 
			return( -1 );
		in = t[7];
	}

	if( thumbnail->auto_rotate &&
		thumbnail->angle != VIPS_ANGLE_D0 ) {
		VipsAngle angle = vips_autorot_get_angle( in );

		g_info( "rotating by %s", 
			vips_enum_nick( VIPS_TYPE_ANGLE, angle ) ); 

		/* Need to copy to memory, we have to stay seq.
		 */
		if( !(t[9] = vips_image_copy_memory( in )) ||
			vips_rot( t[9], &t[10], angle, NULL ) ||
			vips_copy( t[10], &t[14], NULL ) )
			return( -1 ); 
		in = t[14];

		vips_autorot_remove_angle( in );
	}

	/* Crop after rotate so we don't need to rotate the crop box.
	 */
	if( thumbnail->crop != VIPS_INTERESTING_NONE ) {
		g_info( "cropping to %dx%d",
			thumbnail->width, thumbnail->height ); 

		/* Need to copy to memory, we have to stay seq.
		 *
		 * FIXME ... could skip the copy if we've rotated.
		 */
		if( !(t[8] = vips_image_copy_memory( in )) ||
			vips_smartcrop( t[8], &t[11], 
				thumbnail->width, thumbnail->height, 
				"interesting", thumbnail->crop,
				NULL ) )
			return( -1 ); 
		in = t[11];
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
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->dispose = vips_thumbnail_dispose;
	gobject_class->finalize = vips_thumbnail_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail_base";
	vobject_class->description = _( "thumbnail generation" );
	vobject_class->build = vips_thumbnail_build;

	/* We mustn't cache these calls, since we open the file or buffer in 
	 * sequential mode.
	 */
	operation_class->flags = VIPS_OPERATION_NOCACHE;

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
		1, VIPS_MAX_COORD, VIPS_MAX_COORD );

	VIPS_ARG_ENUM( class, "size", 114, 
		_( "size" ), 
		_( "Only upsize, only downsize, or both" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, size ),
		VIPS_TYPE_SIZE, VIPS_SIZE_BOTH ); 

	VIPS_ARG_BOOL( class, "no_rotate", 115, 
		_( "No rotate" ), 
		_( "Don't use orientation tags to rotate image upright" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, no_rotate ),
		FALSE ); 

	VIPS_ARG_ENUM( class, "crop", 116, 
		_( "Crop" ), 
		_( "Reduce to fill target rectangle, then crop" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, crop ),
		VIPS_TYPE_INTERESTING, VIPS_INTERESTING_NONE ); 

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

	VIPS_ARG_ENUM( class, "intent", 120, 
		_( "Intent" ), 
		_( "Rendering intent" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnail, intent ),
		VIPS_TYPE_INTENT, VIPS_INTENT_RELATIVE );

	/* BOOL args which default TRUE arguments don't work with the 
	 * command-line -- GOption does not allow --auto-rotate=false.
	 *
	 * This is now replaced (though still functional) with "no-rotate",
	 * see above.
	 */
	VIPS_ARG_BOOL( class, "auto_rotate", 121, 
		_( "Auto rotate" ), 
		_( "Use orientation tags to rotate image upright" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsThumbnail, auto_rotate ),
		TRUE ); 

}

static void
vips_thumbnail_init( VipsThumbnail *thumbnail )
{
	thumbnail->width = 1;
	thumbnail->height = VIPS_MAX_COORD;
	thumbnail->auto_rotate = TRUE;
	thumbnail->intent = VIPS_INTENT_RELATIVE;
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

	vips_thumbnail_read_header( thumbnail, image );

	g_object_unref( image );

	return( 0 );
}

/* Open an image, pre-shrinking as appropriate. 
 */
static VipsImage *
vips_thumbnail_file_open( VipsThumbnail *thumbnail, double factor )
{
	VipsThumbnailFile *file = (VipsThumbnailFile *) thumbnail;

	if( vips_isprefix( "VipsForeignLoadJpeg", thumbnail->loader ) ) {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadOpenslide", 
		thumbnail->loader ) ) {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"level", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadPdf", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadWebp", thumbnail->loader ) ) {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", 1.0 / factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadTiff", thumbnail->loader ) ) {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"page", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadHeif", thumbnail->loader ) ) {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			"thumbnail", (int) factor,
			NULL ) );
	}
	else {
		return( vips_image_new_from_file( file->filename, 
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) );
	}
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
 * @out: (out): output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize, both or force
 * * @no_rotate: %gboolean, don't rotate upright using orientation tag
 * * @crop: #VipsInteresting, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_profile: %gchararray, fallback import ICC profile
 * * @export_profile: %gchararray, export ICC profile
 * * @intent: #VipsIntent, rendering intent
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
 * @height rectangle, with any excess cropped away. See vips_smartcrop() for
 * details on the cropping strategy.
 *
 * Normally the operation will upsize or downsize as required to fit the image
 * inside or outside the target size. If @size is set
 * to #VIPS_SIZE_UP, the operation will only upsize and will just
 * copy if asked to downsize. 
 * If @size is set
 * to #VIPS_SIZE_DOWN, the operation will only downsize and will just
 * copy if asked to upsize. 
 * If @size is #VIPS_SIZE_FORCE, the image aspect ratio will be broken and the
 * image will be forced to fit the target. 
 *
 * Normally any orientation tags on the input image (such as EXIF tags) are
 * interpreted to rotate the image upright. If you set @no_rotate to %TRUE,
 * these tags will not be interpreted.
 *
 * Shrinking is normally done in sRGB colourspace. Set @linear to shrink in 
 * linear light colourspace instead. This can give better results, but can
 * also be far slower, since tricks like JPEG shrink-on-load cannot be used in
 * linear space.
 *
 * If you set @export_profile to the filename of an ICC profile, the image 
 * will be transformed to the target colourspace before writing to the 
 * output. You can also give an @import_profile which will be used if the 
 * input image has no ICC profile, or if the profile embedded in the 
 * input image is broken.
 *
 * Use @intent to set the rendering intent for any ICC transform. The default
 * is #VIPS_INTENT_RELATIVE.
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
	char *option_string;
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
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string, NULL )) )
		return( -1 );

	vips_thumbnail_read_header( thumbnail, image );

	g_object_unref( image );

	return( 0 );
}

/* Open an image, scaling as appropriate. 
 */
static VipsImage *
vips_thumbnail_buffer_open( VipsThumbnail *thumbnail, double factor )
{
	VipsThumbnailBuffer *buffer = (VipsThumbnailBuffer *) thumbnail;

	if( vips_isprefix( "VipsForeignLoadJpeg", thumbnail->loader ) ) {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadOpenslide", 
		thumbnail->loader ) ) {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"level", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadPdf", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadWebp", thumbnail->loader ) ) {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", 1.0 / factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadTiff", thumbnail->loader ) ) {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"page", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadHeif", thumbnail->loader ) ) {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"thumbnail", (int) factor,
			NULL ) );
	}
	else {
		return( vips_image_new_from_buffer( 
			buffer->buf->data, buffer->buf->length, 
			buffer->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) );
	}
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

	VIPS_ARG_STRING( class, "option_string", 20,
		_( "Extra options" ),
		_( "Options that are passed on to the underlying loader" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnailBuffer, option_string ),
		"" );
}

static void
vips_thumbnail_buffer_init( VipsThumbnailBuffer *buffer )
{
}

/**
 * vips_thumbnail_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize, both or force
 * * @no_rotate: %gboolean, don't rotate upright using orientation tag
 * * @crop: #VipsInteresting, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_profile: %gchararray, fallback import ICC profile
 * * @export_profile: %gchararray, export ICC profile
 * * @intent: #VipsIntent, rendering intent
 * * @option_string: %gchararray, extra loader options
 *
 * Exacty as vips_thumbnail(), but read from a memory buffer. One extra
 * optional argument, @option_string, lets you pass options to the underlying
 * loader.
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

typedef struct _VipsThumbnailSource {
	VipsThumbnail parent_object;

	VipsSource *source;
	char *option_string;
} VipsThumbnailSource;

typedef VipsThumbnailClass VipsThumbnailSourceClass;

G_DEFINE_TYPE( VipsThumbnailSource, vips_thumbnail_source, 
	vips_thumbnail_get_type() );

/* Get the info from a source.
 */
static int
vips_thumbnail_source_get_info( VipsThumbnail *thumbnail )
{
	VipsThumbnailSource *source = (VipsThumbnailSource *) thumbnail;

	VipsImage *image;

	g_info( "thumbnailing source" ); 

	if( !(thumbnail->loader = vips_foreign_find_load_source( 
			source->source )) ||
		!(image = vips_image_new_from_source( source->source, 
			source->option_string, NULL )) )
		return( -1 );

	vips_thumbnail_read_header( thumbnail, image );

	g_object_unref( image );

	return( 0 );
}

/* Open an image, scaling as appropriate. 
 */
static VipsImage *
vips_thumbnail_source_open( VipsThumbnail *thumbnail, double factor )
{
	VipsThumbnailSource *source = (VipsThumbnailSource *) thumbnail;

	if( vips_isprefix( "VipsForeignLoadJpeg", thumbnail->loader ) ) {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadOpenslide", 
		thumbnail->loader ) ) {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"level", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadPdf", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadSvg", thumbnail->loader ) ||
		vips_isprefix( "VipsForeignLoadWebp", thumbnail->loader ) ) {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"scale", 1.0 / factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadTiff", thumbnail->loader ) ) {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"page", (int) factor,
			NULL ) );
	}
	else if( vips_isprefix( "VipsForeignLoadHeif", thumbnail->loader ) ) {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"thumbnail", (int) factor,
			NULL ) );
	}
	else {
		return( vips_image_new_from_source( 
			source->source, 
			source->option_string,
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) );
	}
}

static void
vips_thumbnail_source_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsThumbnailClass *thumbnail_class = VIPS_THUMBNAIL_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail_source";
	vobject_class->description = _( "generate thumbnail from source" );

	thumbnail_class->get_info = vips_thumbnail_source_get_info;
	thumbnail_class->open = vips_thumbnail_source_open;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsThumbnailSource, source ),
		VIPS_TYPE_SOURCE );

	VIPS_ARG_STRING( class, "option_string", 20,
		_( "Extra options" ),
		_( "Options that are passed on to the underlying loader" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThumbnailSource, option_string ),
		"" );

}

static void
vips_thumbnail_source_init( VipsThumbnailSource *source )
{
}

/**
 * vips_thumbnail_source:
 * @source: source to thumbnail
 * @out: (out): output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize, both or force
 * * @no_rotate: %gboolean, don't rotate upright using orientation tag
 * * @crop: #VipsInteresting, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_profile: %gchararray, fallback import ICC profile
 * * @export_profile: %gchararray, export ICC profile
 * * @intent: #VipsIntent, rendering intent
 * * @option_string: %gchararray, extra loader options
 *
 * Exacty as vips_thumbnail(), but read from a source. One extra
 * optional argument, @option_string, lets you pass options to the underlying
 * loader.
 *
 * See also: vips_thumbnail().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thumbnail_source( VipsSource *source, VipsImage **out, int width, ... )
{
	va_list ap;
	int result;

	va_start( ap, width );
	result = vips_call_split( "thumbnail_source", ap, source, out, width );
	va_end( ap );

	return( result );
}

typedef struct _VipsThumbnailImage {
	VipsThumbnail parent_object;

	VipsImage *in;
} VipsThumbnailImage;

typedef VipsThumbnailClass VipsThumbnailImageClass;

G_DEFINE_TYPE( VipsThumbnailImage, vips_thumbnail_image, 
	vips_thumbnail_get_type() );

/* Get the info from a image.
 */
static int
vips_thumbnail_image_get_info( VipsThumbnail *thumbnail )
{
	VipsThumbnailImage *image = (VipsThumbnailImage *) thumbnail;

	/* Doesn't really matter what we put here.
	 */
	thumbnail->loader = "image source";

	vips_thumbnail_read_header( thumbnail, image->in );

	return( 0 );
}

/* Open an image. We can't pre-shrink with an image source, sadly.
 */
static VipsImage *
vips_thumbnail_image_open( VipsThumbnail *thumbnail, double factor )
{
	VipsThumbnailImage *image = (VipsThumbnailImage *) thumbnail;

	g_object_ref( image->in ); 

	return( image->in ); 
}

static void
vips_thumbnail_image_class_init( VipsThumbnailClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsThumbnailClass *thumbnail_class = VIPS_THUMBNAIL_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "thumbnail_image";
	vobject_class->description = _( "generate thumbnail from image" );

	thumbnail_class->get_info = vips_thumbnail_image_get_info;
	thumbnail_class->open = vips_thumbnail_image_open;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsThumbnailImage, in ) );

}

static void
vips_thumbnail_image_init( VipsThumbnailImage *image )
{
}

/**
 * vips_thumbnail_image: (method)
 * @in: input image
 * @out: (out): output image
 * @width: target width in pixels
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @height: %gint, target height in pixels
 * * @size: #VipsSize, upsize, downsize, both or force
 * * @no_rotate: %gboolean, don't rotate upright using orientation tag
 * * @crop: #VipsInteresting, shrink and crop to fill target
 * * @linear: %gboolean, perform shrink in linear light
 * * @import_profile: %gchararray, fallback import ICC profile
 * * @export_profile: %gchararray, export ICC profile
 * * @intent: #VipsIntent, rendering intent
 *
 * Exacty as vips_thumbnail(), but read from an existing image. 
 *
 * This operation
 * is not able to exploit shrink-on-load features of image load libraries, so
 * it can be much slower than `vips_thumbnail()` and produce poorer quality
 * output. Only use it if you really have to.
 *
 * See also: vips_thumbnail().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thumbnail_image( VipsImage *in, VipsImage **out, int width, ... )
{
	va_list ap;
	int result;

	va_start( ap, width );
	result = vips_call_split( "thumbnail_image", ap, in, out, width );
	va_end( ap );

	return( result );
}
