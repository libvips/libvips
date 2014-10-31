/* 
 * compile with:
 *
 *      g++ -g -Wall try.cc `pkg-config vips-cc --cflags --libs`
 *
 */

#define DEBUG

#include <vips/vips8>

using namespace vips8;

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

{ 
	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL_UNBUFFERED ) ); 

	VImage out = in.embed( 10, 10, 1000, 1000, 
		VImage::option()->set( "extend", VIPS_EXTEND_BACKGROUND )->
		set( "background", 128 ) );

	out.write_to_file( "embed.jpg" );
}

{ 
	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL_UNBUFFERED ) ); 
	double a[] = { 1.0, 2.0, 3.0 }; 
	double b[] = { 4.0, 5.0, 6.0 }; 

	std::vector<double> avec( a, a + VIPS_NUMBER( a ) ); 
	std::vector<double> bvec( b, b + VIPS_NUMBER( b ) ); 

	VImage out = in.linear( avec, bvec ); 

	out.write_to_file( "linear.jpg" );
}

{ 
	VImage in = VImage::new_from_file( argv[1], 
		VImage::option()->set( "access", VIPS_ACCESS_SEQUENTIAL_UNBUFFERED ) ); 
	VImage out = in.linear( 1, 2 ); 

	out.write_to_file( "linear1.jpg" );
}

{ 
	VImage in = VImage::new_from_file( argv[1] ); 
	VImage out = in.new_from_image( 128 );

	out.write_to_file( "const.jpg" );
}

	vips_shutdown();

        return( 0 );
}
