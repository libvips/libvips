#include <vips/vips.h>

extern "C" int
LLVMFuzzerInitialize( int *argc, char ***argv )
{
	vips_concurrency_set( 1 );
	return( 0 );
}

static int
test_one_file( const char *name )
{
	VipsImage *image;
	void *buf;
	size_t len;

	if( !(image = vips_image_new_from_file( name, 
		"access", VIPS_ACCESS_SEQUENTIAL, 
		NULL )) )
		return( 0 );

	if( image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4 ) {
		g_object_unref( image );
		return( 0 );
	}

	if( vips_jpegsave_buffer( image, &buf, &len, NULL ) ) {
		g_object_unref( image );
		return( 0 );
	}

	g_free( buf );
	g_object_unref( image );

	return( 0 );
}

extern "C" int
LLVMFuzzerTestOneInput( const guint8 *data, size_t size )
{
	char *name;

	if( size > 100 * 1024 * 1024 )
		return( 0 );

	if( !(name = vips__temp_name( "%s" )) )
		return( 0 );

	if( !g_file_set_contents( name, (const char *) data, size, NULL ) ||
		test_one_file( name ) ) {
		g_unlink( name );
		g_free( name );

		return( 0 );
	}

	g_unlink( name );
	g_free( name );

	return( 0 );
}
