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
 * 30/6/14
 * 	- fix interlaced thumbnail output, thanks lovell
 * 3/8/14
 * 	- box shrink less, use interpolator more, if window_size is large
 * 	  enough
 * 	- default to bicubic if available
 * 	- add an anti-alias filter between shrink and affine
 * 	- support CMYK
 * 	- use SEQ_UNBUF for a memory saving
 * 12/9/14
 * 	- try with embedded profile first, if that fails retry with fallback
 * 	  profile
 * 13/1/15
 * 	- exit with an error code if one or more conversions failed
 * 20/1/15
 * 	- rename -o as -f, keep -o as a hidden flag
 * 9/5/15
 * 	- use vips_resize() instead of our own code
 * 	- premultiply alpha
 * 30/7/15
 * 	- warn if you autorot and there's no exif support
 * 9/2/16
 * 	- add PDF --size support
 * 	- add SVG --size support
 * 28/2/16
 * 	- add webp --shrink support
 * 29/2/16
 * 	- deprecate sharpen and interpolate
 * 6/5/16
 * 	- restore BandFmt after unpremultiply
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
#include <vips/internal.h>

/* Default settings. We change the default to bicubic in main() if
 * this vips has been compiled with bicubic support.
 */

static char *thumbnail_size = "128";
static int thumbnail_width = 128;
static int thumbnail_height = 128;
static char *output_format = "tn_%s.jpg";
static char *export_profile = NULL;
static char *import_profile = NULL;
static gboolean delete_profile = FALSE;
static gboolean linear_processing = FALSE;
static gboolean crop_image = FALSE;
static gboolean rotate_image = FALSE;

/* Deprecated and unused.
 */
static gboolean nosharpen = FALSE;
static gboolean nodelete_profile = FALSE;
static gboolean verbose = FALSE;
static char *convolution_mask = NULL;
static char *interpolator = NULL;

static GOptionEntry options[] = {
	{ "size", 's', 0, 
		G_OPTION_ARG_STRING, &thumbnail_size, 
		N_( "shrink to SIZE or to WIDTHxHEIGHT" ), 
		N_( "SIZE" ) },
	{ "output", 'o', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_STRING, &output_format, 
		N_( "set output to FORMAT" ), 
		N_( "FORMAT" ) },
	{ "format", 'f', 0, 
		G_OPTION_ARG_STRING, &output_format, 
		N_( "set output format string to FORMAT" ), 
		N_( "FORMAT" ) },
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
	{ "interpolator", 'p', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_STRING, &interpolator, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ "sharpen", 'r', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_STRING, &convolution_mask, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ NULL }
};

/* Calculate the shrink factor, taking into account auto-rotate, the fit mode,
 * and so on.
 */
static double
calculate_shrink( VipsImage *im )
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
	 *
	 * Add a small amount so when vips_resize() later rounds down, we
	 * don't round below target.
	 */
	double horizontal = (double) width / (thumbnail_width + 0.1);
	double vertical = (double) height / (thumbnail_height + 0.1);

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
thumbnail_find_jpegshrink( VipsImage *im )
{
	double shrink = calculate_shrink( im ); 

	/* We can't use pre-shrunk images in linear mode. libjpeg shrinks in Y
	 * (of YCbCR), not linear space.
	 */
	if( linear_processing )
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

static VipsImage *
thumbnail_shrink( VipsObject *process, VipsImage *in )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 10 );
	VipsInterpretation interpretation = linear_processing ?
		VIPS_INTERPRETATION_XYZ : VIPS_INTERPRETATION_sRGB; 

	/* TRUE if we've done the import of an ICC transform and still need to
	 * export.
	 */
	gboolean have_imported;

	/* TRUE if we've premultiplied and need to unpremultiply.
	 */
	gboolean have_premultiplied;
	VipsBandFormat unpremultiplied_format;

	/* Sniff the incoming image and try to guess what the alpha max is.
	 */
	double max_alpha;

	double shrink; 

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

	/* Try to guess what the maximum alpha might be.
	 */
	max_alpha = 255;
	if( in->BandFmt == VIPS_FORMAT_USHORT )
		max_alpha = 65535;

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
	if( (linear_processing ||
		in->Type == VIPS_INTERPRETATION_CMYK) &&
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

		have_imported = TRUE;
	}

	/* To the processing colourspace. This will unpack LABQ as well.
	 */
	vips_info( "vipsthumbnail", "converting to processing space %s",
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, interpretation ) ); 
	if( vips_colourspace( in, &t[2], interpretation, NULL ) ) 
		return( NULL ); 
	in = t[2];

	/* If there's an alpha, we have to premultiply before shrinking. See
	 * https://github.com/jcupitt/libvips/issues/291
	 */
	have_premultiplied = FALSE;
	if( in->Bands == 2 ||
		(in->Bands == 4 && in->Type != VIPS_INTERPRETATION_CMYK) ||
		in->Bands == 5 ) {
		vips_info( "vipsthumbnail", "premultiplying alpha" ); 
		if( vips_premultiply( in, &t[3], 
			"max_alpha", max_alpha,
			NULL ) ) 
			return( NULL );
		have_premultiplied = TRUE;

		/* vips_premultiply() makes a float image. When we
		 * vips_unpremultiply() below, we need to cast back to the
		 * pre-premultiply format.
		 */
		unpremultiplied_format = in->BandFmt;
		in = t[3];
	}

	shrink = calculate_shrink( in );

	if( vips_resize( in, &t[4], 1.0 / shrink, NULL ) ) 
		return( NULL );
	in = t[4];

	if( have_premultiplied ) {
		vips_info( "vipsthumbnail", "unpremultiplying alpha" ); 
		if( vips_unpremultiply( in, &t[5], 
			"max_alpha", max_alpha,
			NULL ) || 
			vips_cast( t[5], &t[6], unpremultiplied_format, NULL ) )
			return( NULL );
		in = t[6];
	}

	/* Colour management.
	 *
	 * If we've already imported, just export. Otherwise, we're in 
	 * device space and we need a combined import/export to transform to 
	 * the target space.
	 */
	if( have_imported ) { 
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
			if( vips_colourspace( in, &t[7], 
				VIPS_INTERPRETATION_sRGB, NULL ) ) 
				return( NULL ); 
			in = t[7];
		}
	}
	else if( export_profile &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 import_profile) ) {
		VipsImage *out;

		vips_info( "vipsthumbnail", 
			"exporting with profile %s", export_profile );

		/* We first try with the embedded profile, if any, then if
		 * that fails try again with the supplied fallback profile.
		 */
		out = NULL; 
		if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
			vips_info( "vipsthumbnail", 
				"importing with embedded profile" );

			if( vips_icc_transform( in, &t[7], export_profile,
				"embedded", TRUE,
				NULL ) ) {
				vips_warn( "vipsthumbnail", 
					_( "unable to import with "
						"embedded profile: %s" ),
					vips_error_buffer() );

				vips_error_clear();
			}
			else
				out = t[7];
		}

		if( !out &&
			import_profile ) { 
			vips_info( "vipsthumbnail", 
				"importing with fallback profile" );

			if( vips_icc_transform( in, &t[7], export_profile,
				"input_profile", import_profile,
				"embedded", FALSE,
				NULL ) )  
				return( NULL );

			out = t[7];
		}

		/* If the embedded profile failed and there's no fallback or
		 * the fallback failed, out will still be NULL.
		 */
		if( out )
			in = out;
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
	VipsImage **t = (VipsImage **) vips_object_local_array( process, 2 );
	VipsAngle angle = vips_autorot_get_angle( im );

	if( rotate_image &&
		angle != VIPS_ANGLE_D0 ) {
		vips_info( "vipsthumbnail", "rotating by %s", 
			vips_enum_nick( VIPS_TYPE_ANGLE, angle ) ); 

		/* Need to copy to memory, we have to stay seq.
		 */
		t[0] = vips_image_new_memory();
		if( vips_image_write( im, t[0] ) ||
			vips_rot( t[0], &t[1], angle, NULL ) )
			return( NULL ); 
		im = t[1];

		vips_autorot_remove_angle( im );
	}

	return( im );
}

/* Given (eg.) "/poop/somefile.png", write @im to the thumbnail name,
 * (eg.) "/poop/tn_somefile.jpg".
 */
static int
thumbnail_write( VipsObject *process, VipsImage *im, const char *filename )
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

	/* Don't use vips_snprintf(), we only want to optionally substitute a 
	 * single %s.
	 */
	vips_strncpy( buf, output_format, FILENAME_MAX ); 
	vips__substitute( buf, FILENAME_MAX, file ); 

	/* output_format can be an absolute path, in which case we discard the
	 * path from the incoming file.
	 */
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

	if( vips_image_write_to_file( im, output_name, NULL ) ) {
		g_free( output_name );
		return( -1 );
	}
	g_free( output_name );

	return( 0 );
}

static int
thumbnail_process( VipsObject *process, const char *filename )
{
	VipsImage *in;
	VipsImage *thumbnail;
	VipsImage *crop;
	VipsImage *rotate;

	if( !(in = thumbnail_open( process, filename )) ||
		!(thumbnail = thumbnail_shrink( process, in )) ||
		!(crop = thumbnail_crop( process, thumbnail )) ||
		!(rotate = thumbnail_rotate( process, crop )) ||
		thumbnail_write( process, rotate, filename ) )
		return( -1 );

	return( 0 );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GOptionGroup *main_group;
	GError *error = NULL;
	int i;
	int result;

	if( VIPS_INIT( argv[0] ) )
	        vips_error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

        context = g_option_context_new( _( "- thumbnail generator" ) );

	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_group_add_entries( main_group, options );
	vips_add_option_entries( main_group ); 
	g_option_group_set_translation_domain( main_group, GETTEXT_PACKAGE );
	g_option_context_set_main_group( context, main_group );

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

	if( rotate_image ) {
#ifndef HAVE_EXIF
		vips_warn( "vipsthumbnail", "%s",
			_( "auto-rotate disabled: "
			      "libvips built without exif support" ) );
#endif /*!HAVE_EXIF*/
	}

	result = 0;

	for( i = 1; i < argc; i++ ) {
		/* Hang resources for processing this thumbnail off @process.
		 */
		VipsObject *process = VIPS_OBJECT( vips_image_new() ); 

		if( thumbnail_process( process, argv[i] ) ) {
			fprintf( stderr, "%s: unable to thumbnail %s\n", 
				argv[0], argv[i] );
			fprintf( stderr, "%s", vips_error_buffer() );
			vips_error_clear();

			/* We had a conversion failure: return an error code
			 * when we finally exit.
			 */
			result = -1;
		}

		g_object_unref( process );
	}

	vips_shutdown();

	return( result );
}
