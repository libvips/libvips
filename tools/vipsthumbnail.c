/* VIPS thumbnailer
 *
 * 11/1/09
 *
 * 13/1/09
 * 	- decode labq and rad images
 * 	- colour management
 * 	- better handling of tiny images
 * 25/1/10
 * 	- added "--delete"
 * 6/2/10
 * 	- added "--interpolator"
 * 	- added "--nosharpen"
 * 	- better 'open' logic, test lazy flag now
 * 13/5/10
 * 	- oops hehe residual sharpen test was reversed
 * 	- and the mask coefficients were messed up
 * 26/5/10
 * 	- delete failed if there was a profile
 * 4/7/10
 * 	- oops sharpening was turning off for integer shrinks, thanks Nicolas
 * 30/7/10
 * 	- use new "rd" mode rather than our own open via disc
 * 8/2/12
 * 	- use :seq mode for png images
 * 	- shrink to a scanline cache to ensure we request pixels sequentially
 * 	  from the input
 * 13/6/12
 * 	- update the sequential stuff to the general method
 * 21/6/12
 * 	- remove "--nodelete" option, have a --delete option instead, off by
 * 	  default
 * 	- much more gentle extra sharpening
 * 13/11/12
 * 	- allow absolute paths in -o (thanks fuho)
 * 3/5/13
 * 	- add optional sharpening mask from file
 * 10/7/13
 * 	- rewrite for vips8
 * 	- handle embedded jpeg thumbnails
 * 12/11/13
 * 	- add --linear option
 * 18/12/13
 * 	- add --crop option
 * 5/3/14
 * 	- copy main image metadata to embedded thumbnails, thanks ottob
 * 6/3/14
 * 	- add --rotate flag
 * 7/3/14
 * 	- remove the embedded thumbnail reader, embedded thumbnails are too
 * 	  unlike the main image wrt. rotation / colour / etc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>

#include <vips/vips.h>

#define ORIENTATION ("exif-ifd0-Orientation")

static char *thumbnail_size = "128";
static int thumbnail_width = 128;
static int thumbnail_height = 128;
static char *output_format = "tn_%s.jpg";
static char *interpolator = "bilinear";
static char *export_profile = NULL;
static char *import_profile = NULL;
static char *convolution_mask = "mild";
static gboolean delete_profile = FALSE;
static gboolean linear_processing = FALSE;
static gboolean crop_image = FALSE;
static gboolean rotate_image = FALSE;

/* Deprecated and unused.
 */
static gboolean nosharpen = FALSE;
static gboolean nodelete_profile = FALSE;
static gboolean verbose = FALSE;

static GOptionEntry options[] = {
	{ "size", 's', 0, 
		G_OPTION_ARG_STRING, &thumbnail_size, 
		N_( "shrink to SIZE or to WIDTHxHEIGHT" ), 
		N_( "SIZE" ) },
	{ "output", 'o', 0, 
		G_OPTION_ARG_STRING, &output_format, 
		N_( "set output to FORMAT" ), 
		N_( "FORMAT" ) },
	{ "interpolator", 'p', 0, 
		G_OPTION_ARG_STRING, &interpolator, 
		N_( "resample with INTERPOLATOR" ), 
		N_( "INTERPOLATOR" ) },
	{ "sharpen", 'r', 0, 
		G_OPTION_ARG_STRING, &convolution_mask, 
		N_( "sharpen with none|mild|MASKFILE" ), 
		N_( "none|mild|MASKFILE" ) },
	{ "eprofile", 'e', 0, 
		G_OPTION_ARG_STRING, &export_profile, 
		N_( "export with PROFILE" ), 
		N_( "PROFILE" ) },
	{ "iprofile", 'i', 0, 
		G_OPTION_ARG_STRING, &import_profile, 
		N_( "import untagged images with PROFILE" ), 
		N_( "PROFILE" ) },
	{ "linear", 'a', 0, 
		G_OPTION_ARG_NONE, &linear_processing, 
		N_( "process in linear space" ), NULL },
	{ "crop", 'c', 0, 
		G_OPTION_ARG_NONE, &crop_image, 
		N_( "crop exactly to SIZE" ), NULL },
	{ "rotate", 't', 0, 
		G_OPTION_ARG_NONE, &rotate_image, 
		N_( "auto-rotate" ), NULL },
	{ "delete", 'd', 0, 
		G_OPTION_ARG_NONE, &delete_profile, 
		N_( "delete profile from exported image" ), NULL },
	{ "verbose", 'v', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &verbose, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ "nodelete", 'l', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &nodelete_profile, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ "nosharpen", 'n', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &nosharpen, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ NULL }
};

static VipsAngle 
get_angle( VipsImage *im )
{
	VipsAngle angle;
	const char *orientation;

	angle = VIPS_ANGLE_0;

	if( vips_image_get_typeof( im, ORIENTATION ) && 
		!vips_image_get_string( im, ORIENTATION, &orientation ) ) {
		if( vips_isprefix( "6", orientation ) )
			angle = VIPS_ANGLE_90;
	}

	return( angle );
}

/* Calculate the shrink factors. 
 *
 * We shrink in two stages: first, a shrink with a block average. This can
 * only accurately shrink by integer factors. We then do a second shrink with
 * a supplied interpolator to get the exact size we want.
 */
static int
calculate_shrink( VipsImage *im, double *residual )
{
	VipsAngle angle = get_angle( im ); 
	gboolean rotate = angle == VIPS_ANGLE_90 || angle == VIPS_ANGLE_270;
	int width = rotate_image && rotate ? im->Ysize : im->Xsize;
	int height = rotate_image && rotate ? im->Xsize : im->Ysize;

	/* Calculate the horizontal and vertical shrink we'd need to fit the
	 * image to the bounding box, and pick the biggest.
	 *
	 * In crop mode we aim to fill the bounding box, so we must use the
	 * smaller axis.
	 */
	double horizontal = (double) width / thumbnail_width;
	double vertical = (double) height / thumbnail_height;
	double factor = crop_image ?
		VIPS_MIN( horizontal, vertical ) : 
		VIPS_MAX( horizontal, vertical ); 

	/* If the shrink factor is <= 1.0, we need to zoom rather than shrink.
	 * Just set the factor to 1 in this case.
	 */
	double factor2 = factor < 1.0 ? 1.0 : factor;

	/* Int component of shrink.
	 */
	int shrink = floor( factor2 );

	if( residual ) {
		/* Width after int shrink.
		 */
		int iwidth = width / shrink;

		/* Therefore residual scale factor is.
		 */
		*residual = (width / factor) / iwidth; 
	}

	return( shrink );
}

/* Find the best jpeg preload shrink.
 */
static int
thumbnail_find_jpegshrink( VipsImage *im )
{
	int shrink = calculate_shrink( im, NULL );

	/* We can't use pre-shrunk images in linear mode. libjpeg shrinks in Y
	 * (of YCbCR), not linear space.
	 */

	if( linear_processing )
		return( 1 ); 
	else if( shrink >= 8 )
		return( 8 );
	else if( shrink >= 4 )
		return( 4 );
	else if( shrink >= 2 )
		return( 2 );
	else 
		return( 1 );
}

/* Open an image, returning the best version of that image for thumbnailing. 
 *
 * libjpeg supports fast shrink-on-read, so if we have a JPEG, we can ask 
 * VIPS to load a lower resolution version.
 */
static VipsImage *
thumbnail_open( VipsObject *process, const char *filename )
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
		if( !(im = vips_image_new_from_file( filename )) )
			return( NULL );

		jpegshrink = thumbnail_find_jpegshrink( im );

		g_object_unref( im );

		vips_info( "vipsthumbnail", 
			"loading jpeg with factor %d pre-shrink", 
			jpegshrink ); 

		if( vips_foreign_load( filename, &im,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"shrink", jpegshrink,
			NULL ) )
			return( NULL );
	}
	else {
		/* All other formats.
		 */
		if( vips_foreign_load( filename, &im,
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL ) )
			return( NULL );
	}

	vips_object_local( process, im );

	return( im ); 
}

static VipsInterpolate *
thumbnail_interpolator( VipsObject *process, VipsImage *in )
{
	double residual;
	VipsInterpolate *interp;

	calculate_shrink( in, &residual );

	/* For images smaller than the thumbnail, we upscale with nearest
	 * neighbor. Otherwise we makes thumbnails that look fuzzy and awful.
	 */
	if( !(interp = VIPS_INTERPOLATE( vips_object_new_from_string( 
		g_type_class_ref( VIPS_TYPE_INTERPOLATE ), 
		residual > 1.0 ? "nearest" : interpolator ) )) )
		return( NULL );

	vips_object_local( process, interp );

	return( interp );
}

/* Some interpolators look a little soft, so we have an optional sharpening
 * stage.
 */
static VipsImage *
thumbnail_sharpen( VipsObject *process )
{
	VipsImage *mask;

	if( strcmp( convolution_mask, "none" ) == 0 ) 
		mask = NULL; 
	else if( strcmp( convolution_mask, "mild" ) == 0 ) {
		mask = vips_image_new_matrixv( 3, 3,
			-1.0, -1.0, -1.0,
			-1.0, 32.0, -1.0,
			-1.0, -1.0, -1.0 );
		vips_image_set_double( mask, "scale", 24 );
	}
	else
		if( !(mask = 
			vips_image_new_from_file( convolution_mask )) )
			vips_error_exit( "unable to load sharpen mask" ); 

	if( mask )
		vips_object_local( process, mask );

	return( mask );
}

static VipsImage *
thumbnail_shrink( VipsObject *process, VipsImage *in, 
	VipsInterpolate *interp, VipsImage *sharpen )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 10 );
	VipsInterpretation interpretation = linear_processing ?
		VIPS_INTERPRETATION_XYZ : VIPS_INTERPRETATION_sRGB; 

	int shrink; 
	double residual; 
	int tile_width;
	int tile_height;
	int nlines;

	/* RAD needs special unpacking.
	 */
	if( in->Coding == VIPS_CODING_RAD ) {
		vips_info( "vipsthumbnail", "unpacking Rad to float" );

		/* rad is scrgb.
		 */
		if( vips_rad2float( in, &t[0], NULL ) )
			return( NULL );
		in = t[0];
	}

	/* In linear mode, we import right at the start. 
	 *
	 * This is only going to work for images in device space. If you have
	 * an image in PCS which also has an attached profile, strange things
	 * will happen. 
	 */
	if( linear_processing &&
		in->Coding == VIPS_CODING_NONE &&
		(in->BandFmt == VIPS_FORMAT_UCHAR ||
		 in->BandFmt == VIPS_FORMAT_USHORT) &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 import_profile) ) {
		if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) )
			vips_info( "vipsthumbnail", 
				"importing with embedded profile" );
		else
			vips_info( "vipsthumbnail", 
				"importing with profile %s", import_profile );

		if( vips_icc_import( in, &t[1], 
			"input_profile", import_profile,
			"embedded", TRUE,
			"pcs", VIPS_PCS_XYZ,
			NULL ) )  
			return( NULL );

		in = t[1];
	}

	/* To the processing colourspace. This will unpack LABQ as well.
	 */
	vips_info( "vipsthumbnail", "converting to processing space %s",
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, interpretation ) ); 
	if( vips_colourspace( in, &t[2], interpretation, NULL ) ) 
		return( NULL ); 
	in = t[2];

	shrink = calculate_shrink( in, &residual );

	vips_info( "vipsthumbnail", "integer shrink by %d", shrink );

	if( vips_shrink( in, &t[3], shrink, shrink, NULL ) ) 
		return( NULL );
	in = t[3];

	/* We want to make sure we read the image sequentially.
	 * However, the convolution we may be doing later will force us 
	 * into SMALLTILE or maybe FATSTRIP mode and that will break
	 * sequentiality.
	 *
	 * So ... read into a cache where tiles are scanlines, and make sure
	 * we keep enough scanlines to be able to serve a line of tiles.
	 *
	 * We use a threaded tilecache to avoid a deadlock: suppose thread1,
	 * evaluating the top block of the output, is delayed, and thread2, 
	 * evaluating the second block, gets here first (this can happen on 
	 * a heavily-loaded system). 
	 *
	 * With an unthreaded tilecache (as we had before), thread2 will get
	 * the cache lock and start evaling the second block of the shrink. 
	 * When it reaches the png reader it will stall until the first block 
	 * has been used ... but it never will, since thread1 will block on 
	 * this cache lock. 
	 */
	vips_get_tile_size( in, 
		&tile_width, &tile_height, &nlines );
	if( vips_tilecache( in, &t[4], 
		"tile_width", in->Xsize,
		"tile_height", 10,
		"max_tiles", (nlines * 2) / 10,
		"access", VIPS_ACCESS_SEQUENTIAL,
		"threaded", TRUE, 
		NULL ) ||
		vips_affine( t[4], &t[5], residual, 0, 0, residual, 
			"interpolate", interp,
			NULL ) )  
		return( NULL );
	in = t[5];

	vips_info( "vipsthumbnail", "residual scale by %g", residual );
	vips_info( "vipsthumbnail", "%s interpolation", 
		VIPS_OBJECT_GET_CLASS( interp )->nickname );

	/* Colour management.
	 *
	 * In linear mode, just export. In device space mode, do a combined
	 * import/export to transform to the target space.
	 */
	if( linear_processing ) {
		if( export_profile ||
			vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
			vips_info( "vipsthumbnail", 
				"exporting to device space with a profile" );
			if( vips_icc_export( in, &t[7], 
				"output_profile", export_profile,
				NULL ) )  
				return( NULL );
			in = t[7];
		}
		else {
			vips_info( "vipsthumbnail", "converting to sRGB" );
			if( vips_colourspace( in, &t[6], 
				VIPS_INTERPRETATION_sRGB, NULL ) ) 
				return( NULL ); 
			in = t[6];
		}
	}
	else if( export_profile &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 import_profile) ) {
		if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) )
			vips_info( "vipsthumbnail", 
				"importing with embedded profile" );
		else
			vips_info( "vipsthumbnail", 
				"importing with profile %s", import_profile );

		vips_info( "vipsthumbnail", 
			"exporting with profile %s", export_profile );

		if( vips_icc_transform( in, &t[6], export_profile,
			"input_profile", import_profile,
			"embedded", TRUE,
			NULL ) )  
			return( NULL );

		in = t[6];
	}

	/* If we are upsampling, don't sharpen, since nearest looks dumb
	 * sharpened.
	 */
	if( shrink >= 1 && 
		residual <= 1.0 && 
		sharpen ) { 
		vips_info( "vipsthumbnail", "sharpening thumbnail" );
		if( vips_conv( in, &t[8], sharpen, NULL ) ) 
			return( NULL );
		in = t[8];
	}

	if( delete_profile &&
		vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
		vips_info( "vipsthumbnail", 
			"deleting profile from output image" );
		if( !vips_image_remove( in, VIPS_META_ICC_NAME ) ) 
			return( NULL );
	}

	return( in );
}

/* Crop down to the final size, if crop_image is set. 
 */
static VipsImage *
thumbnail_crop( VipsObject *process, VipsImage *im )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 2 );

	if( crop_image ) {
		int left = (im->Xsize - thumbnail_width) / 2;
		int top = (im->Ysize - thumbnail_height) / 2;

		if( vips_extract_area( im, &t[0], left, top, 
			thumbnail_width, thumbnail_height, NULL ) )
			return( NULL ); 
		im = t[0];
	}

	return( im );
}

/* Auto-rotate, if rotate_image is set. 
 */
static VipsImage *
thumbnail_rotate( VipsObject *process, VipsImage *im )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 1 );

	if( rotate_image ) {
		if( vips_rot( im, &t[0], get_angle( im ), NULL ) )
			return( NULL ); 
		im = t[0];

		(void) vips_image_remove( im, ORIENTATION );
	}

	return( im );
}

/* Given (eg.) "/poop/somefile.png", write @im to the thumbnail name,
 * (eg.) "/poop/tn_somefile.jpg".
 */
static int
thumbnail_write( VipsImage *im, const char *filename )
{
	char *file;
	char *p;
	char buf[FILENAME_MAX];
	char *output_name;

	file = g_path_get_basename( filename );

	/* Remove the suffix from the file portion.
	 */
	if( (p = strrchr( file, '.' )) ) 
		*p = '\0';

	/* output_format can be an absolute path, in which case we discard the
	 * path from the incoming file.
	 */
	vips_snprintf( buf, FILENAME_MAX, output_format, file );
	if( g_path_is_absolute( output_format ) ) 
		output_name = g_strdup( buf );
	else {
		char *dir;

		dir = g_path_get_dirname( filename );
		output_name = g_build_filename( dir, buf, NULL );
		g_free( dir );
	}

	vips_info( "vipsthumbnail", 
		"thumbnailing %s as %s", filename, output_name );

	g_free( file );

	if( vips_image_write_to_file( im, output_name ) ) {
		g_free( output_name );
		return( -1 );
	}
	g_free( output_name );

	return( 0 );
}

static int
thumbnail_process( VipsObject *process, const char *filename )
{
	VipsImage *sharpen = thumbnail_sharpen( process );

	VipsImage *in;
	VipsInterpolate *interp;
	VipsImage *thumbnail;
	VipsImage *crop;
	VipsImage *rotate;

	if( !(in = thumbnail_open( process, filename )) ||
		!(interp = thumbnail_interpolator( process, in )) ||
		!(thumbnail = 
			thumbnail_shrink( process, in, interp, sharpen )) ||
		!(crop = thumbnail_crop( process, thumbnail )) ||
		!(rotate = thumbnail_rotate( process, crop )) ||
		thumbnail_write( rotate, filename ) )
		return( -1 );

	return( 0 );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GError *error = NULL;
	int i;

	if( vips_init( argv[0] ) )
	        vips_error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

        context = g_option_context_new( _( "- thumbnail generator" ) );

	g_option_context_add_main_entries( context, options, GETTEXT_PACKAGE );
	g_option_context_add_group( context, vips_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( "try \"%s --help\"", g_get_prgname() );
	}

	g_option_context_free( context );

	if( sscanf( thumbnail_size, "%d x %d", 
		&thumbnail_width, &thumbnail_height ) != 2 ) {
		if( sscanf( thumbnail_size, "%d", &thumbnail_width ) != 1 ) 
			vips_error_exit( "unable to parse size \"%s\" -- "
				"use eg. 128 or 200x300", thumbnail_size );

		thumbnail_height = thumbnail_width;
	}

	for( i = 1; i < argc; i++ ) {
		/* Hang resources for processing this thumbnail off @process.
		 */
		VipsObject *process = VIPS_OBJECT( vips_image_new() ); 

		if( thumbnail_process( process, argv[i] ) ) {
			fprintf( stderr, "%s: unable to thumbnail %s\n", 
				argv[0], argv[i] );
			fprintf( stderr, "%s", vips_error_buffer() );
			vips_error_clear();
		}

		g_object_unref( process );
	}

	vips_shutdown();

	return( 0 );
}
