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
	if( vips_init( argv[0] ) )
		vips_error_exit( NULL ); 

	printf( "these should match if VImage is compile-time-only\n" ); 
	printf( "sizeof( VipsImage *) = %zd\n", sizeof( VipsImage *) ); 
	printf( "sizeof( VImage ) = %zd\n", sizeof( VImage ) ); 

	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL ) ); 

	VImage out; 

	out = in.invert();

	out.write_to_file( argv[2] );

	vips_shutdown();

        return( 0 );
}
