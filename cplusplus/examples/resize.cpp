/* compile with:
 *
 *      g++ -g -Wall resize.cpp `pkg-config vips-cpp --cflags --libs`
 */

#include <vips/vips8>

using namespace vips;

int
main( int argc, char **argv )
{
	if( VIPS_INIT( argv[0] ) )
		vips_error_exit( NULL ); 

	VImage in = VImage::new_from_file( argv[1], VImage::option()
		->set( "access", "sequential" ) ); 

	VImage out = in.resize( 0.2, VImage::option()
		->set( "kernel", "cubic" )
		->set( "vscale", 0.2 ) );

	out.write_to_file( argv[2] );

	vips_shutdown();

        return( 0 );
}
