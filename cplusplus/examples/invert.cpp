/* 
 * compile with:
 *
 *      g++ -g -Wall invert.cpp `pkg-config vips-cpp --cflags --libs`
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

	if( vips_init( argv[0] ) )
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


	printf( "these should match if VImage is compile-time-only\n" ); 
	printf( "sizeof( VipsImage *) = %zd\n", sizeof( VipsImage *) ); 
	printf( "sizeof( VImage ) = %zd\n", sizeof( VImage ) ); 

{ 
	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL_UNBUFFERED ) ); 

	VImage out; 

	out = in.invert();

	out.write_to_file( argv[2] );
}

	vips_shutdown();

        return( 0 );
}
