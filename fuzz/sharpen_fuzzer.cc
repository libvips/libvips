#include <vips/vips.h>

// Unpublised libjxl API.
void SetDecoderMemoryLimitBase_(size_t memory_limit_base);

extern "C" int
LLVMFuzzerInitialize( int *argc, char ***argv )
{
	vips_concurrency_set( 1 );
	SetDecoderMemoryLimitBase_(1 << 20);
	return( 0 );
}

extern "C" int
LLVMFuzzerTestOneInput( const guint8 *data, size_t size )
{
	VipsImage *image, *out;
	double d;

	if( size > 100 * 1024 * 1024 )
		return( 0 );

	if( !(image = vips_image_new_from_buffer( data, size, "", NULL )) ) 
		return( 0 );

	if( image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4 ) {
		g_object_unref( image );
		return( 0 );
	}

	if( vips_sharpen( image, &out, NULL ) ) {
		g_object_unref( image );
		return( 0 );
	}

	vips_avg( out, &d, NULL );

	g_object_unref( out );
	g_object_unref( image );

	return( 0 );
}
