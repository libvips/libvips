/* 
 * compile with:
 *
 *      g++ -g -Wall resize.cpp `pkg-config vips-cpp --cflags --libs`
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
	VInterpolate interp = VInterpolate::new_from_name( "nohalo" );

	VImage out; 

	out = in.resize( 0.2, VImage::option()->set( "interpolate", interp ) );

	out.write_to_file( argv[2] );

	vips_shutdown();

        return( 0 );
}
