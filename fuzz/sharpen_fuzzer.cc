#include <vips/vips.h>

extern "C" int
LLVMFuzzerInitialize( int *argc, char ***argv )
{
	vips_concurrency_set( 1 );
	return( 0 );
}

extern "C" int
LLVMFuzzerTestOneInput( const guint8 *data, size_t size )
{
	VipsImage *in, *out;
	double d;

	if( !(in = vips_image_new_from_buffer( data, size, "", NULL )) ) {
		return( 0 );
	}

	if( vips_sharpen( in, &out, NULL ) ) {
		g_object_unref( in );
		return( 0 );
	}

	vips_avg( out, &d, NULL );

	g_object_unref( out );
	g_object_unref( in );

	return( 0 );
}
