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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>

static int thumbnail_size = 128;
static char *output_format = "tn_%s.jpg";
static int use_disc_threshold = 1024 * 1024;
static char *interpolator = "bilinear";;
static gboolean nosharpen = FALSE;
static char *export_profile = NULL;
static char *import_profile = NULL;
static gboolean nodelete_profile = FALSE;
static gboolean verbose = FALSE;

static GOptionEntry options[] = {
	{ "size", 's', 0, G_OPTION_ARG_INT, &thumbnail_size, 
		N_( "set thumbnail size to N" ), "N" },
	{ "output", 'o', 0, G_OPTION_ARG_STRING, &output_format, 
		N_( "set output to S" ), "S" },
	{ "disc", 'd', 0, G_OPTION_ARG_INT, &use_disc_threshold, 
		N_( "set disc use threshold to N" ), "N" },
	{ "interpolator", 'p', 0, G_OPTION_ARG_STRING, &interpolator, 
		N_( "resample with interpolator I" ), "I" },
	{ "nosharpen", 'n', 0, G_OPTION_ARG_NONE, &nosharpen, 
		N_( "don't sharpen thumbnail" ), NULL },
	{ "eprofile", 'e', 0, G_OPTION_ARG_STRING, &export_profile, 
		N_( "export with profile P" ), "P" },
	{ "iprofile", 'i', 0, G_OPTION_ARG_STRING, &import_profile, 
		N_( "import untagged images with profile P" ), "P" },
	{ "nodelete", 'l', 0, G_OPTION_ARG_NONE, &nodelete_profile, 
		N_( "don't delete profile from exported image" ), NULL },
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, 
		N_( "verbose output" ), NULL },
	{ NULL }
};

/* Open an image, using a disc temporary for 'large' images.
 */
static IMAGE *
open_image( const char *filename )
{
	IMAGE *im;
	size_t size;
	VipsFormatClass *format;

	/* Normally we'd just im_open() the filename. But we want to control
	 * the process, so we use the lower-level API.
	 */

	/* Find a format and check the flags. Does this format support lazy
	 * load? If it does, we can just open the image directly.
	 */
	if( !(format = vips_format_for_file( filename )) )
		return( NULL );
	if( vips_format_get_flags( format, filename ) & VIPS_FORMAT_PARTIAL ) {
		if( verbose )
			printf( "format supports lazy read, "
				"working directly from disc file\n" ); 

		return( im_open( filename, "r" ) );
	}

	/* Get the header and try to predict uncompressed image size.
	 */
	if( !(im = im_open( "header", "p" )) )
		return( NULL );
	if( format->header( filename, im ) ) {
		im_close( im );
		return( NULL );
	}
	size = IM_IMAGE_SIZEOF_LINE( im ) * im->Ysize;
	im_close( im );

	/* If it's less than our threshold, decompress to memory. 
	 */
	if( size < use_disc_threshold ) {
		if( verbose )
			printf( "small file, decompressing to memory\n" ); 

		if( !(im = im_open( filename, "t" )) )
			return( NULL );
	}
	else {
		/* This makes a disc temp which be unlinked automatically 
		 * when 'im' is closed. The temp is made in "/tmp", or 
		 * "$TMPDIR/", if the environment variable is set.
		 */
		if( !(im = im__open_temp( "%s.v" )) ) 
			return( NULL );

		if( verbose )
			printf( "large file, decompressing to disc temp %s\n", 
				im->filename );
	}

	/* Load into im, which is memory or disc, depending.
	 */
	if( format->load( filename, im ) ) {
		im_close( im );
		return( NULL );
	}

	return( im );
}

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
			-1, 16, -1, 
			-1, -1, -1 );
		mask->scale = 8;
	}

	return( mask );
}

static int
shrink_factor( IMAGE *in, IMAGE *out, 
	int shrink, double residual, VipsInterpolate *interp )
{
	IMAGE *t[9];
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
	 */
	if( im_shrink( x, t[2], shrink, shrink ) ||
		im_affinei_all( t[2], t[3], 
			interp, residual, 0, 0, residual, 0, 0 ) )
		return( -1 );
	x = t[3];

	/* If we are upsampling, don't sharpen, since nearest looks dumb
	 * sharpened.
	 */
	if( residual < 1.0 && !nosharpen ) {
		if( verbose ) 
			printf( "sharpening thumbnail\n" );

		if( im_conv( x, t[4], sharpen_filter() ) )
			return( -1 );
		x = t[4];
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

			if( im_icc_import_embedded( x, t[5], 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );
		}
		else {
			if( verbose ) 
				printf( "importing with profile %s\n",
					import_profile );

			if( im_icc_import( x, t[5], 
				import_profile, 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );
		}

		if( verbose ) 
			printf( "exporting with profile %s\n", export_profile );

		if( im_icc_export_depth( t[5], t[6], 
			8, export_profile, 
			IM_INTENT_RELATIVE_COLORIMETRIC ) )
			return( -1 );

		x = t[6];
	}

	if( !nodelete_profile ) {
		if( verbose )
			printf( "deleting profile from output image\n" );

		if( im_meta_remove( x, IM_META_ICC_NAME ) )
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
		"VipsInterpolate", 
		residual > 1.0 ? "nearest" : interpolator ) )) )
		return( -1 );

	if( verbose ) {
		printf( "integer shrink by %d\n", shrink );
		printf( "residual scale by %g\n", residual );
		printf( "%s interpolation\n", VIPS_OBJECT( interp )->nickname );
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
thumbnail2( const char *filename )
{
	IMAGE *in;
	IMAGE *out;
	char *tn_filename;
	int result;

	if( !(in = open_image( filename )) )
		return( -1 );

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

	if( verbose )
		printf( "thumbnailing %s\n", filename );

	if( !(format = vips_format_for_file( filename )) )
		return( -1 );

	if( verbose )
		printf( "detected format as %s\n", 
			VIPS_OBJECT_CLASS( format )->nickname );

	if( strcmp( VIPS_OBJECT_CLASS( format )->nickname, "jpeg" ) == 0 ) {
		IMAGE *im;
		int shrink;
		char buf[FILENAME_MAX];

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

		im_snprintf( buf, FILENAME_MAX, "%s:%d", filename, shrink );

		if( verbose )
			printf( "using fast jpeg shrink, factor %d\n", shrink );

		return( thumbnail2( buf ) );
	}
	else 
		return( thumbnail2( filename ) );
}

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GError *error = NULL;
	int i;

	im_init_world( argv[0] );

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

	return( 0 );
}
