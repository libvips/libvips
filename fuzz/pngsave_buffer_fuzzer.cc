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
	VipsImage *image;
	void *buf;
	size_t len;

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

	if( vips_pngsave_buffer( image, &buf, &len, NULL ) ) {
		g_object_unref( image );
		return( 0 );
	}

	g_free( buf );
	g_object_unref( image );

	return( 0 );
}
