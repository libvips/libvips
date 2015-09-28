/* 
 * compile with:
 *
 *      g++ -g -Wall buffer.cpp `pkg-config vips-cpp --cflags --libs`
 *
 */

#define DEBUG

#include <vips/vips8>

using namespace vips;

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GOptionGroup *main_group;
	GError *error = NULL;

	if( VIPS_INIT( argv[0] ) )
		vips_error_exit( NULL ); 

	context = g_option_context_new( "" ); 

	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_context_set_main_group( context, main_group );
	g_option_context_add_group( context, vips_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( NULL );
	}

	// load an image from a file
	VImage im = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", "sequential-unbuffered" ) ); 
	printf( "loaded %d x %d pixel image from %s\n", 
		im.width(), im.height(), argv[1] ); 

	// write to a formatted memory buffer
	size_t size;
	void *buf;
	im.write_to_buffer( ".png", &buf, &size );
	printf( "written to memory %p in png format, %zu bytes\n", buf, size );

	// load from the formatted memory area
	im = VImage::new_from_buffer( buf, size, "" );
	printf( "loaded from memory, %d x %d pixel image\n", 
		im.width(), im.height() ); 

	// write back to a file
	im.write_to_file( argv[2] );
	printf( "written back to  %s\n", argv[2] ); 

        return( 0 );
}
