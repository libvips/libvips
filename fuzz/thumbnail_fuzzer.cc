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
	size_t width, height;
	double d;

	if( !(in = vips_image_new_from_buffer( data, size, "", NULL )) ) {
		return( 0 );
	}

	width = in->Xsize;
	height = in->Ysize;

	/* Skip big images. It is likely to timeout.
	 */
	if ( width * height > 256 * 256 ) {
		g_object_unref( in );
		return( 0 );
	}

	if( vips_thumbnail_image( in, &out, 42, NULL ) ) {
		g_object_unref( in );
		return( 0 );
	}

	vips_avg( out, &d, NULL );

	g_object_unref( out );
	g_object_unref( in );

	return( 0 );
}
