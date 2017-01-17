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
 * 23/5/16
 * 	- no need to guess max-alpha now premultiply does this for us
 * 1/8/16
 * 	- use scRGB as the working space in linear mode
 * 15/8/16
 * 	- can now remove 0.1 rounding adjustment
 * 2/11/16
 * 	- use vips_thumbnail(), most code moved there
 * 6/1/17
 * 	- fancy geometry strings
 * 	- support VipSize restrictions
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
static VipsSize size_restriction = VIPS_SIZE_BOTH;
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

	g_info( "thumbnailing %s as %s", filename, output_name );

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
	VipsImage *image;

	if( vips_thumbnail( filename, &image, thumbnail_width, 
		"height", thumbnail_height, 
		"size", size_restriction, 
		"auto_rotate", rotate_image, 
		"crop", crop_image, 
		"linear", linear_processing, 
		"import_profile", import_profile, 
		"export_profile", export_profile, 
		NULL ) )
		return( -1 );

	if( thumbnail_write( process, image, filename ) ) {
		g_object_unref( image ); 
		return( -1 );
	}

	g_object_unref( image ); 

	return( 0 );
}

/* Fetch a match_info string, NULL for "".
 */
static const char *
fetch_match( GMatchInfo *match_info, int n )
{
	const char *str = g_match_info_fetch( match_info, n );

	return( str && strcmp( str, "" ) == 0 ? NULL : str );
}

/* Parse a geometry string and set thumbnail_width and thumbnail_height.
 */
static int
thumbnail_parse_geometry( const char *geometry )
{
	GRegex *regex;
	GMatchInfo *match_info;
	gboolean handled;

	handled = FALSE;

	regex = g_regex_new( "^(\\d+)? (x)? (\\d+)? ([<>])?$", 
		G_REGEX_CASELESS | G_REGEX_EXTENDED, 0, NULL );
	g_regex_match( regex, geometry, 0, &match_info );
	if( g_match_info_matches( match_info ) ) {
		const char *w = fetch_match( match_info, 1 );
		const char *x = fetch_match( match_info, 2 );
		const char *h = fetch_match( match_info, 3 );
		const char *s = fetch_match( match_info, 4 );

		/* If --crop is set, both width and height must be specified,
		 * since we'll need a complete bounding box to fill.
		 */
		if( crop_image && x && (!w || !h) ) {
			vips_error( "thumbnail",
				"both width and height must be given if "
				"--crop is enabled" );
			return( -1 );
		}

		if( !x ) { 
			/* No "x" means we only allow a single number and it 
			 * sets both width and height.
			 */
			if( w && !h ) {
				thumbnail_width = thumbnail_height = atoi( w );
				handled = TRUE;
			}
			if( !w && h ) {
				thumbnail_width = thumbnail_height = atoi( h );
				handled = TRUE;
			}
		}
		else { 
			/* w or h missing means replace with a huuuge value 
			 * to prevent reduction or enlargement in that axis.
			 */
			thumbnail_width = VIPS_MAX_COORD;
			thumbnail_height = VIPS_MAX_COORD;
			if( w ) {
				thumbnail_width = atoi( w );
				handled = TRUE;
			}
			if( h ) {
				thumbnail_height = atoi( h );
				handled = TRUE;
			}
		}

		if( s && strcmp( s, ">" ) == 0 )
			size_restriction = VIPS_SIZE_DOWN;
		if( s && strcmp( s, "<" ) == 0 )
			size_restriction = VIPS_SIZE_UP;
	}

	g_match_info_free( match_info );
	g_regex_unref( regex );

	if( !handled ) {
		vips_error( "thumbnail",
			"unable to parse size \"%s\" -- "
			"use eg. 128 or 200x300>", geometry );

		return( -1 );
	}

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

	/* The operation cache is not useful for processing many files.
	vips_cache_set_max( 0 );
	 */

	/* On Windows, argv is ascii-only .. use this to get a utf-8 version of
	 * the args.
	 */
#ifdef HAVE_G_WIN32_GET_COMMAND_LINE
	argv = g_win32_get_command_line();
#endif /*HAVE_G_WIN32_GET_COMMAND_LINE*/

        context = g_option_context_new( _( "- thumbnail generator" ) );

	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_group_add_entries( main_group, options );
	vips_add_option_entries( main_group ); 
	g_option_group_set_translation_domain( main_group, GETTEXT_PACKAGE );
	g_option_context_set_main_group( context, main_group );

#ifdef HAVE_G_WIN32_GET_COMMAND_LINE
	if( !g_option_context_parse_strv( context, &argv, &error ) ) 
#else /*!HAVE_G_WIN32_GET_COMMAND_LINE*/
	if( !g_option_context_parse( context, &argc, &argv, &error ) ) 
#endif /*HAVE_G_WIN32_GET_COMMAND_LINE*/
	{
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( "try \"%s --help\"", g_get_prgname() );
	}

	g_option_context_free( context );

	if( thumbnail_size && 
		thumbnail_parse_geometry( thumbnail_size ) )
		vips_error_exit( NULL ); 

#ifndef HAVE_EXIF
	if( rotate_image ) 
		g_warning( "%s",
			_( "auto-rotate disabled: "
			      "libvips built without exif support" ) );
#endif /*!HAVE_EXIF*/

	result = 0;

	for( i = 1; argv[i]; i++ ) {
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

	/* We don't free this on error exit, sadly.
	 */
#ifdef HAVE_G_WIN32_GET_COMMAND_LINE
	g_strfreev( argv ); 
#endif /*HAVE_G_WIN32_GET_COMMAND_LINE*/

	vips_shutdown();

	return( result );
}
