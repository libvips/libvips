/* 
 * compile with:
 *
 *      g++ -g -Wall try.cc `pkg-config vips-cc --cflags --libs`
 *
 */

#define DEBUG

#include <vips/vips8>

using namespace vips8;

template <typename A, typename B, typename C> 
C test_add( T left, T right )
{
	return( left + right );
}

std::vector<double> 
get_pixel( VImage x, int x, int y )
{
	VImage pixel = x.extract_area( x, y, 1, 1 );
	std::vector<VImage> split = pixel.bandsplit()
	std::vector<double> values( split.bands() ); 

	for( int i = 0; i < split.bands(); i++ )
		values[i] = split.avg(); 
	
	return( values ); 
}

void
test_binary
{

}

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


{ 
	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL_UNBUFFERED ) ); 
	double avg;

	avg = in.avg(); 

	printf( "avg = %g\n", avg ); 
}

        return( 0 );
}
