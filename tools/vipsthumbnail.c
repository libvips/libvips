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
static char *interpolator = "bilinear";;
static gboolean nosharpen = FALSE;
static char *export_profile = NULL;
static char *import_profile = NULL;
static gboolean delete_profile = FALSE;
static gboolean nodelete_profile = FALSE;
static gboolean verbose = FALSE;

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
	{ "nosharpen", 'n', 0, 
		G_OPTION_ARG_NONE, &nosharpen, 
		N_( "don't sharpen thumbnail" ), NULL },
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
	{ "nodelete", 'l', G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &nodelete_profile, 
		N_( "(deprecated, does nothing)" ), NULL },
	{ "verbose", 'v', 0, 
		G_OPTION_ARG_NONE, &verbose, 
		N_( "verbose output" ), NULL },
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

/* Some interpolators look a little soft, so we have an optional sharpening
 * stage.
 */
static INTMASK *
sharpen_filter( void )
{
	static INTMASK *mask = NULL;

	if( !mask ) {
		mask = im_create_imaskv( "sharpen.con", 3, 3, 
			-1, -1, -1, 
			-1, 32, -1, 
			-1, -1, -1 );
		mask->scale = 24;
	}

	return( mask );
}

static int
shrink_factor( IMAGE *in, IMAGE *out, 
	int shrink, double residual, VipsInterpolate *interp )
{
	IMAGE *t[9];
	VipsImage **s = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 1 );
	IMAGE *x;

	if( im_open_local_array( out, t, 9, "thumbnail", "p" ) )
		return( -1 );
	x = in;

	/* Unpack the two coded formats we support to float for processing.
	 */
	if( x->Coding == IM_CODING_LABQ ) {
		if( verbose ) 
			printf( "unpacking LAB to RGB\n" );

		if( im_LabQ2disp( x, t[1], im_col_displays( 7 ) ) )
			return( -1 );
		x = t[1];
	}
	else if( x->Coding == IM_CODING_RAD ) {
		if( verbose ) 
			printf( "unpacking Rad to float\n" );

		if( im_rad2float( x, t[1] ) )
			return( -1 );
		x = t[1];
	}

	/* Shrink! 
	 *
	 * We want to make sure we read the image sequentially.
	 * However, the convolution we may be doing later will force us 
	 * into SMALLTILE or maybe FATSTRIP mode and that will break
	 * sequentiality.
	 *
	 * So ... read into a cache where tiles are scanlines, and make sure
	 * we keep enough scanlines to be able to serve a line of tiles.
	 */
	if( im_shrink( x, t[2], shrink, shrink ) ||
		vips_tilecache( t[2], &s[0], 
			"tile_width", t[2]->Xsize,
			"tile_height", 1,
			"max_tiles", VIPS__TILE_HEIGHT * 2,
			"strategy", VIPS_CACHE_SEQUENTIAL,
			NULL ) ||
		im_affinei_all( s[0], t[4], 
			interp, residual, 0, 0, residual, 0, 0 ) )
		return( -1 );
	x = t[4];

	/* If we are upsampling, don't sharpen, since nearest looks dumb
	 * sharpened.
	 */
	if( shrink > 1 && residual <= 1.0 && !nosharpen ) {
		if( verbose ) 
			printf( "sharpening thumbnail\n" );

		if( im_conv( x, t[5], sharpen_filter() ) )
			return( -1 );
		x = t[5];
	}

	/* Colour management: we can transform the image if we have an output
	 * profile and an input profile. The input profile can be in the
	 * image, or if there is no profile there, supplied by the user.
	 */
	if( export_profile &&
		(im_header_get_typeof( x, IM_META_ICC_NAME ) || 
		 import_profile) ) {
		if( im_header_get_typeof( x, IM_META_ICC_NAME ) ) {
			if( verbose ) 
				printf( "importing with embedded profile\n" );

			if( im_icc_import_embedded( x, t[6], 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );
		}
		else {
			if( verbose ) 
				printf( "importing with profile %s\n",
					import_profile );

			if( im_icc_import( x, t[6], 
				import_profile, 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );
		}

		if( verbose ) 
			printf( "exporting with profile %s\n", export_profile );

		if( im_icc_export_depth( t[6], t[7], 
			8, export_profile, 
			IM_INTENT_RELATIVE_COLORIMETRIC ) )
			return( -1 );

		x = t[7];
	}

	if( delete_profile ) {
		if( verbose )
			printf( "deleting profile from output image\n" );

		/* Only try to remove if it exists to avoid extra error
		 * messages.
		 */
		if( im_meta_get_typeof( x, IM_META_ICC_NAME ) &&
			!im_meta_remove( x, IM_META_ICC_NAME ) )
			return( -1 );
	}

	if( im_copy( x, out ) )
		return( -1 );

	return( 0 );
}

static int
thumbnail3( IMAGE *in, IMAGE *out )
{
	int shrink;
	double residual;
	VipsInterpolate *interp;
	int result;

	shrink = calculate_shrink( in->Xsize, in->Ysize, &residual );

	/* For images smaller than the thumbnail, we upscale with nearest
	 * neighbor. Otherwise we makes thumbnails that look fuzzy and awful.
	 */
	if( !(interp = VIPS_INTERPOLATE( vips_object_new_from_string( 
		g_type_class_ref( VIPS_TYPE_INTERPOLATE ), 
		residual > 1.0 ? "nearest" : interpolator ) )) )
		return( -1 );

	if( verbose ) {
		printf( "integer shrink by %d\n", shrink );
		printf( "residual scale by %g\n", residual );
		printf( "%s interpolation\n", 
			VIPS_OBJECT_GET_CLASS( interp )->nickname );
	}

	result = shrink_factor( in, out, shrink, residual, interp );

	g_object_unref( interp );

	return( result );
}

/* Given (eg.) "/poop/somefile.png", make the thumbnail name,
 * "/poop/tn_somefile.jpg".
 */
static char *
make_thumbnail_name( const char *filename )
{
	char *dir;
	char *file;
	char *p;
	char buf[FILENAME_MAX];
	char *result;

	dir = g_path_get_dirname( filename );
	file = g_path_get_basename( filename );

	if( (p = strrchr( file, '.' )) ) 
		*p = '\0';

	im_snprintf( buf, FILENAME_MAX, output_format, file );
	result = g_build_filename( dir, buf, NULL );

	if( verbose )
		printf( "thumbnailing %s as %s\n", filename, buf );

	g_free( dir );
	g_free( file );

	return( result );
}

static int
thumbnail2( const char *filename, int shrink )
{
	IMAGE *in;
	IMAGE *out;
	char *tn_filename;
	int result;

	/* Open in sequential mode.
	 */
	if( shrink > 1 ) {
		if( vips_foreign_load( filename, &in,
			"sequential", TRUE,
			"shrink", shrink,
			NULL ) )
			return( -1 );
	}
	else {
		if( vips_foreign_load( filename, &in,
			"sequential", TRUE,
			NULL ) )
			return( -1 );
	}

	tn_filename = make_thumbnail_name( filename );
	if( !(out = im_open( tn_filename, "w" )) ) {
		im_close( in );
		g_free( tn_filename );
		return( -1 );
	}

	result = thumbnail3( in, out );

	g_free( tn_filename );
	im_close( out );
	im_close( in );

	return( result );
}

/* JPEGs get special treatment. libjpeg supports fast shrink-on-read,
 * so if we have a JPEG, we can ask VIPS to load a lower resolution
 * version.
 */
static int
thumbnail( const char *filename )
{
	VipsFormatClass *format;
	int shrink;

	if( verbose )
		printf( "thumbnailing %s\n", filename );

	if( !(format = vips_format_for_file( filename )) )
		return( -1 );

	if( verbose )
		printf( "detected format as %s\n", 
			VIPS_OBJECT_CLASS( format )->nickname );

	shrink = 1;
	if( strcmp( VIPS_OBJECT_CLASS( format )->nickname, "jpeg" ) == 0 ) {
		IMAGE *im;

		/* This will just read in the header and is quick.
		 */
		if( !(im = im_open( filename, "r" )) )
			return( -1 );
		shrink = calculate_shrink( im->Xsize, im->Ysize, NULL );
		im_close( im );

		if( shrink > 8 )
			shrink = 8;
		else if( shrink > 4 )
			shrink = 4;
		else if( shrink > 2 )
			shrink = 2;
		else 
			shrink = 1;

		if( verbose )
			printf( "using fast jpeg shrink, factor %d\n", shrink );
	}

	return( thumbnail2( filename, shrink ) );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GError *error = NULL;
	int i;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

        context = g_option_context_new( _( "- thumbnail generator" ) );

	g_option_context_add_main_entries( context, options, GETTEXT_PACKAGE );
	g_option_context_add_group( context, im_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		error_exit( "try \"%s --help\"", g_get_prgname() );
	}

	g_option_context_free( context );

	for( i = 1; i < argc; i++ )
		if( thumbnail( argv[i] ) ) {
			fprintf( stderr, "%s: unable to thumbnail %s\n", 
				argv[0], argv[i] );
			fprintf( stderr, "%s", im_error_buffer() );
			im_error_clear();
		}

	vips_shutdown();

	return( 0 );
}
