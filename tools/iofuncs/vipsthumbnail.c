/* VIPS thumbnailer
 *
 * J. Cupitt, 11/1/09
 *
 * 13/1/09
 * 	- don't shrink images that are already tiny
 * 	- decode labq and rad images
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

static gboolean verbose = FALSE;
static int use_disc_threshold = 1024 * 1024;
static int thumbnail_size = 128;
static char *thumbnail_format = "tn_%s.jpg";
static char *export_profile = NULL;
static char *import_profile = NULL;

static GOptionEntry options[] = {
	{ "size", 's', 0, G_OPTION_ARG_INT, &thumbnail_size, 
		N_( "set thumbnail size to N" ), "N" },
	{ "format", 'f', 0, G_OPTION_ARG_STRING, &thumbnail_format, 
		N_( "set thumbnail format to S" ), "S" },
	{ "disc", 'd', 0, G_OPTION_ARG_INT, &use_disc_threshold, 
		N_( "set disc use threshold to N" ), "N" },
	{ "eprofile", 'e', 0, G_OPTION_ARG_STRING, &export_profile, 
		N_( "export with profile P" ), "P" },
	{ "iprofile", 'i', 0, G_OPTION_ARG_STRING, &import_profile, 
		N_( "import untagged images with profile P" ), "P" },
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
	IMAGE *disc;
	size_t size;
	VipsFormatClass *format;

	if( !(im = im_open( filename, "r" )) )
		return( NULL );

	/* Estimate decompressed image size.
	 */
	size = IM_IMAGE_SIZEOF_LINE( im ) * im->Ysize;

	/* If it's less than a megabyte, we can just use 'im'. This will
	 * decompress to memory.
	 */
	if( size < use_disc_threshold )
		return( im );

	/* Nope, too big, we need to decompress to disc and return the disc
	 * file.
	 */
	im_close( im );

	/* This makes a disc temp which be unlinked automatically when the
	 * image is closed. The temp is made in "/tmp", or "$TMPDIR/", if the
	 * environment variable is set.
	 */
	if( !(disc = im__open_temp( "%s.v" )) ) 
		return( NULL );

	if( verbose )
		printf( "large file, decompressing to disc temp %s\n", 
			disc->filename );

	/* Find a decompress class and use it to load the image.
	 */
	if( !(format = vips_format_for_file( filename )) || 
                format->load( filename, disc ) ) {
		im_close( disc );
		return( NULL );
	}

	return( disc );
}

/* Calculate the shrink factors. 
 *
 * We shrink in two stages: first, a shrink with a block average. This can
 * only accurately shrink by integer factors. We then do a second shrink with
 * bilinear interpolation to get the exact size we want.
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

/* We use bilinear interpolation for the final shrink. VIPS has higher-order
 * interpolators, but they are only built if a C++ compiler is available.
 * Bilinear can look a little 'soft', so after shrinking, we need to sharpen a
 * little.
 *
 * This is a simple sharpen filter.
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
shrink_factor( IMAGE *in, IMAGE *out )
{
	IMAGE *t[9];
	IMAGE *x;
	int shrink;
	double residual;
	VipsInterpolate *interp;

	shrink = calculate_shrink( in->Xsize, in->Ysize, &residual );

	/* For images smaller than the thumbnail, we upscale with nearest
	 * neighbor. Otherwise we makes thumbnails that look fuzzy and awful.
	 */
	if( residual > 1.0 )
		interp = vips_interpolate_nearest_static();
	else
		interp = vips_interpolate_bilinear_static();

	if( verbose ) {
		printf( "integer shrink by %d\n", shrink );
		printf( "residual scale by %g\n", residual );
	}

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
	if( residual > 1.0 ) {
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
			if( im_icc_import_embedded( x, t[5], 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );

			if( verbose ) 
				printf( "importing with embedded profile\n" );
		}
		else {
			if( im_icc_import( x, t[5], 
				import_profile, 
				IM_INTENT_RELATIVE_COLORIMETRIC ) )
				return( -1 );

			if( verbose ) 
				printf( "importing with profile %s\n",
					import_profile );
		}

		if( im_icc_export_depth( t[5], t[6], 
			8, export_profile, 
			IM_INTENT_RELATIVE_COLORIMETRIC ) )
			return( -1 );

		if( verbose ) 
			printf( "exporting with profile %s\n", export_profile );

		x = t[6];
	}

	if( im_copy( x, out ) )
		return( -1 );

	return( 0 );
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

	im_snprintf( buf, FILENAME_MAX, thumbnail_format, file );
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

	result = shrink_factor( in, out );

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
