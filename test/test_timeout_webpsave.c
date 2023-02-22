#include <vips/vips.h>

#define TIMEOUT_SECONDS 2

static void
progress_callback(VipsImage *image, VipsProgress *progress, void *pdata)
{
	if( progress->run >= TIMEOUT_SECONDS )
		vips_image_set_kill( image, TRUE );
}

int main()
{
	VipsImage *in;
	void *buf;
	size_t len;
	int r;

	in = vips_image_new_from_file( "max_dim_webp.png", NULL );
	if( in == NULL )
		return( -1 );
	vips_image_set_progress( in, TRUE );
	g_signal_connect( in, "eval", G_CALLBACK( progress_callback ), NULL );
	r = vips_webpsave_buffer( in, &buf, &len, NULL );
	/* Error expected due to timeout
	 */
	g_object_unref( in );
	if( r == 0 ) {
		g_free( buf );
		return( -1 );
	}
	return( 0 );
}
