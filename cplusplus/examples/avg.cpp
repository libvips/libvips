/* 
 * compile with:
 *
 *      g++ -g -Wall avg.cpp `pkg-config vips-cpp --cflags --libs`
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

	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL ) ); 
	double avg;

	avg = in.avg(); 

	printf( "avg = %g\n", avg ); 

	vips_shutdown();

        return( 0 );
}
