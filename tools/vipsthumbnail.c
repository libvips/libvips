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

static int thumbnail_size = 128;
static char *output_format = "tn_%s.jpg";
static char *interpolator = "bilinear";
static char *export_profile = NULL;
static char *import_profile = NULL;
static char *convolution_mask = "mild";
static gboolean delete_profile = FALSE;
static gboolean verbose = FALSE;

/* Deprecated and unused.
 */
static gboolean nosharpen = FALSE;
static gboolean nodelete_profile = FALSE;

static GOptionEntry options[] = {
	{ "size", 's', 0, 
		G_OPTION_ARG_INT, &thumbnail_size, 
		N_( "set thumbnail size to SIZE" ), 
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
	{ "delete", 'd', 0, 
		G_OPTION_ARG_NONE, &delete_profile, 
		N_( "delete profile from exported image" ), NULL },
	{ "verbose", 'v', 0, 
		G_OPTION_ARG_NONE, &verbose, 
		N_( "verbose output" ), NULL },
	{ "nodelete", 'l', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &nodelete_profile, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ "nosharpen", 'n', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &nosharpen, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ NULL }
};

/* Calculate the shrink factors. 
 *
 * We shrink in two stages: first, a shrink with a block average. This can
 * only accurately shrink by integer factors. We then do a second shrink with
 * a supplied interpolator to get the exact size we want.
 */
static int
calculate_shrink( int width, int height, double *residual )
{
	/* We shrink to make the largest dimension equal to size.
	 */
	int dimension = IM_MAX( width, height );

	double factor = dimension / (double) thumbnail_size;

	/* If the shrink factor is <=1.0, we need to zoom rather than shrink.
	 * Just set the factor to 1 in this case.
	 */
	double factor2 = factor < 1.0 ? 1.0 : factor;

	/* Int component of shrink.
	 */
	int shrink = floor( factor2 );

	/* Size after int shrink.
	 */
	int isize = floor( dimension / shrink );

	/* Therefore residual scale factor is.
	 */
	if( residual )
		*residual = thumbnail_size / (double) isize;

	return( shrink );
}

/* Find the best jpeg preload shrink.
 */
static int
thumbnail_find_jpegshrink( VipsImage *im )
{
	int shrink;

	shrink = calculate_shrink( im->Xsize, im->Ysize, NULL );

	if( shrink >= 8 )
		return( 8 );
	else if( shrink >= 4 )
		return( 4 );
	else if( shrink >= 2 )
		return( 2 );
	else 
		return( 1 );
}

#define THUMBNAIL "jpeg-thumbnail-data"

/* Try to read an embedded thumbnail. 
 */
static VipsImage *
thumbnail_get_thumbnail( VipsImage *im )
{
	void *ptr;
	size_t size;
	VipsImage *thumb;
	double residual;
	int jpegshrink;

	if( !vips_image_get_typeof( im, THUMBNAIL ) ||
		vips_image_get_blob( im, THUMBNAIL, &ptr, &size ) ||
		vips_jpegload_buffer( ptr, size, &thumb, NULL ) ) {
		if( verbose )
			printf( "no jpeg thumbnail\n" ); 
		return( NULL ); 
	}

	calculate_shrink( thumb->Xsize, thumb->Ysize, &residual );
	if( residual > 1.0 ) { 
		if( verbose )
			printf( "jpeg thumbnail too small\n" ); 
		g_object_unref( thumb ); 
		return( NULL ); 
	}

	/* Reload with the correct downshrink.
	 */
	jpegshrink = thumbnail_find_jpegshrink( thumb );
	if( verbose )
		printf( "loading jpeg thumbnail with factor %d pre-shrink\n", 
			jpegshrink );
	g_object_unref( thumb );
	if( vips_jpegload_buffer( ptr, size, &thumb, 
		"shrink", jpegshrink,
		NULL ) ) {
		if( verbose )
			printf( "jpeg thumbnail reload failed\n" ); 
		return( NULL ); 
	}

	if( verbose )
		printf( "using %dx%d jpeg thumbnail\n", 
			thumb->Xsize, thumb->Ysize ); 

	return( thumb );
}

/* Open an image, returning the best version of that image for thumbnailing. 
 *
 * jpegs can have embedded thumbnails ... use that if it's large enough.
 *
 * libjpeg supports fast shrink-on-read, so if we have a JPEG, we can ask 
 * VIPS to load a lower resolution version.
 */
static VipsImage *
thumbnail_open( VipsObject *thumbnail, const char *filename )
{
	const char *loader;
	VipsImage *im;

	if( verbose )
		printf( "thumbnailing %s\n", filename );

	if( !(loader = vips_foreign_find_load( filename )) )
		return( NULL );

	if( verbose )
		printf( "selected loader is \"%s\"\n", loader ); 

	if( strcmp( loader, "VipsForeignLoadJpegFile" ) == 0 ) {
		VipsImage *thumb;

		/* This will just read in the header and is quick.
		 */
		if( !(im = vips_image_new_from_file( filename )) )
			return( NULL );

		/* Try to read an embedded thumbnail. If we find one, use that
		 * instead.
		 */
		if( (thumb = thumbnail_get_thumbnail( im )) ) { 
			/* @thumb has not been fully decoded yet ... 
			 * we must not close @im
			 * until we're done with @thumb.
			 */
			vips_object_local( VIPS_OBJECT( thumb ), im );

			im = thumb;
		}
		else {
			int jpegshrink;

			if( verbose )
				printf( "processing main jpeg image\n" );

			jpegshrink = thumbnail_find_jpegshrink( im );

			g_object_unref( im );

			if( verbose )
				printf( "loading jpeg with factor %d "
					"pre-shrink\n", jpegshrink ); 

			if( vips_foreign_load( filename, &im,
				"sequential", TRUE,
				"shrink", jpegshrink,
				NULL ) )
				return( NULL );
		}
	}
	else {
		/* All other formats.
		 */
		if( vips_foreign_load( filename, &im,
			"sequential", TRUE,
			NULL ) )
			return( NULL );
	}

	vips_object_local( thumbnail, im );

	return( im ); 
}

static VipsImage *
thumbnail_shrink( VipsObject *thumbnail, VipsImage *in, 
	VipsInterpolate *interp, INTMASK *sharpen )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( thumbnail, 10 );

	int shrink; 
	double residual; 
	int tile_width;
	int tile_height;
	int nlines;

	/* Unpack the two coded formats we support.
	 */
	if( in->Coding == VIPS_CODING_LABQ ) {
		if( verbose ) 
			printf( "unpacking LAB to RGB\n" );

		if( vips_colourspace( in, &t[0], 
			VIPS_INTERPRETATION_sRGB, NULL ) ) 
			return( NULL ); 

		in = t[0];
	}
	else if( in->Coding == IM_CODING_RAD ) {
		if( verbose ) 
			printf( "unpacking Rad to float\n" );

		/* rad is scrgb.
		 */
		if( vips_rad2float( in, &t[1], NULL ) ||
			vips_colourspace( t[1], &t[2], 
				VIPS_INTERPRETATION_sRGB, NULL ) ) 
			return( NULL );

		in = t[2];
	}

	shrink = calculate_shrink( in->Xsize, in->Ysize, &residual );

	if( verbose ) 
		printf( "integer shrink by %d\n", shrink );

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
	 */
	vips_get_tile_size( in, 
		&tile_width, &tile_height, &nlines );
	if( vips_tilecache( in, &t[4], 
		"tile_width", in->Xsize,
		"tile_height", 10,
		"max_tiles", (nlines * 2) / 10,
		"strategy", VIPS_CACHE_SEQUENTIAL,
		NULL ) ||
		vips_affine( t[4], &t[5], residual, 0, 0, residual, NULL, 
			"interpolate", interp,
			NULL ) )  
		return( NULL );
	in = t[5];

	if( verbose ) {
		printf( "residual scale by %g\n", residual );
		printf( "%s interpolation\n", 
			VIPS_OBJECT_GET_CLASS( interp )->nickname );
	}

	/* If we are upsampling, don't sharpen, since nearest looks dumb
	 * sharpened.
	 */
	if( shrink >= 1 && 
		residual <= 1.0 && 
		sharpen ) { 
		if( verbose ) 
			printf( "sharpening thumbnail\n" );

		t[6] = vips_image_new();
		if( im_conv( in, t[6], sharpen ) ) 
			return( NULL );
		in = t[6];
	}

	/* Colour management: we can transform the image if we have an output
	 * profile and an input profile. The input profile can be in the
	 * image, or if there is no profile there, supplied by the user.
	 */
	if( export_profile &&
		(vips_image_get_typeof( in, VIPS_META_ICC_NAME ) || 
		 import_profile) ) {
		if( verbose ) {
			if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) )
				printf( "importing with embedded profile\n" );
			else
				printf( "importing with profile %s\n",
					import_profile );

			printf( "exporting with profile %s\n", export_profile );
		}

		if( vips_icc_transform( in, &t[7], export_profile,
			"input_profile", import_profile,
			"embedded", TRUE,
			NULL ) )  
			return( NULL );

		in = t[7];
	}

	if( delete_profile &&
		vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
		if( verbose )
			printf( "deleting profile from output image\n" );

		if( vips_image_remove( in, VIPS_META_ICC_NAME ) ) 
			return( NULL );
	}

	return( in );
}

static VipsInterpolate *
thumbnail_interpolator( VipsObject *thumbnail, VipsImage *in )
{
	double residual;
	VipsInterpolate *interp;

	calculate_shrink( in->Xsize, in->Ysize, &residual );

	/* For images smaller than the thumbnail, we upscale with nearest
	 * neighbor. Otherwise we makes thumbnails that look fuzzy and awful.
	 */
	if( !(interp = VIPS_INTERPOLATE( vips_object_new_from_string( 
		g_type_class_ref( VIPS_TYPE_INTERPOLATE ), 
		residual > 1.0 ? "nearest" : interpolator ) )) )
		return( NULL );

	vips_object_local( thumbnail, interp );

	return( interp );
}

/* Some interpolators look a little soft, so we have an optional sharpening
 * stage.
 */
static INTMASK *
thumbnail_sharpen( void )
{
	static INTMASK *mask = NULL;

	if( !mask )  {
		if( strcmp( convolution_mask, "none" ) == 0 ) 
			mask = NULL; 
		else if( strcmp( convolution_mask, "mild" ) == 0 ) {
			mask = im_create_imaskv( "sharpen.con", 3, 3,
				-1, -1, -1,
				-1, 32, -1,
				-1, -1, -1 );
			mask->scale = 24;
		}
		else
			if( !(mask = im_read_imask( convolution_mask )) )
				vips_error_exit( "unable to load sharpen" );
	}

	return( mask );
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

	if( verbose )
		printf( "thumbnailing %s as %s\n", filename, output_name );

	g_free( file );

	if( vips_image_write_to_file( im, output_name ) ) {
		g_free( output_name );
		return( -1 );
	}
	g_free( output_name );

	return( 0 );
}

static int
thumbnail_process( VipsObject *thumbnail, const char *filename )
{
	VipsImage *in;
	VipsInterpolate *interp;
	INTMASK *sharpen;
	VipsImage *thumb;

	if( !(in = thumbnail_open( thumbnail, filename )) )
		return( -1 );
	if( !(interp = thumbnail_interpolator( thumbnail, in )) )
		return( -1 );
	sharpen = thumbnail_sharpen();
	if( !(thumb = thumbnail_shrink( thumbnail, in, interp, sharpen )) )
		return( -1 );
	if( thumbnail_write( thumb, filename ) )
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

	for( i = 1; i < argc; i++ ) {
		/* Hang resources for this processing off this.
		 */
		VipsObject *thumbnail = VIPS_OBJECT( vips_image_new() ); 

		if( thumbnail_process( thumbnail, argv[i] ) ) {
			fprintf( stderr, "%s: unable to thumbnail %s\n", 
				argv[0], argv[i] );
			fprintf( stderr, "%s", vips_error_buffer() );
			vips_error_clear();
		}

		g_object_unref( thumbnail );
	}

	vips_shutdown();

	return( 0 );
}
