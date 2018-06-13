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
	if( VIPS_INIT( argv[0] ) )
		vips_error_exit( NULL ); 

	// load an image from a file
	VImage im = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", "sequential" ) ); 
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
