#include <vips/vips.h>

struct mosaic_opt {
	guint8 dir : 1;
	guint16 xref;
	guint16 yref;
	guint16 xsec;
	guint16 ysec;
};

extern "C" int
LLVMFuzzerInitialize( int *argc, char ***argv )
{
	vips_concurrency_set( 1 );
	return( 0 );
}

extern "C" int
LLVMFuzzerTestOneInput( const guint8 *data, size_t size )
{
	VipsImage *ref, *sec, *out;
	struct mosaic_opt *opt;
	double d;

	if( size < sizeof(struct mosaic_opt) )
		return( 0 );

	if( !(ref = vips_image_new_from_buffer( data, size, "", NULL )) )
		return( 0 );

	/* Skip big images. They are likely to timeout.
	 */
	if( ref->Xsize > 1024 ||
	    ref->Ysize > 1024 ||
	    ref->Bands > 10 ) {
		g_object_unref( ref );
		return( 0 );
	}

	if( vips_rot180( ref, &sec, NULL ) ) {
		g_object_unref( ref );
		return( 0 );
	}

	/* Extract some bytes from the tail to fuzz the arguments of the API.
	 */
	opt = (struct mosaic_opt *) (data + size - sizeof(struct mosaic_opt));

	if( vips_mosaic( ref, sec, &out, (VipsDirection) opt->dir,
	                 opt->xref, opt->yref, opt->xsec, opt->ysec, NULL ) ) {
		g_object_unref( sec );
		g_object_unref( ref );
		return( 0 );
	}

	vips_max( out, &d, NULL );

	g_object_unref( out );
	g_object_unref( sec );
	g_object_unref( ref );

	return( 0 );
}
