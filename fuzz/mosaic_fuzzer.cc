#include <vips/vips.h>

struct mosaic_opt {
	guint8 dir : 1;
	guint16 xref;
	guint16 yref;
	guint16 xsec;
	guint16 ysec;
} __attribute__ ((packed));

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
	mosaic_opt opt = {};
	double d;

	if( size < sizeof( mosaic_opt ) )
		return( 0 );

	if( size > 100 * 1024 * 1024 )
		return( 0 );

	/* The beginning of `data` is treated as mosaic configuration
	 */
	memcpy( &opt, data, sizeof( mosaic_opt ) );

	/* Remainder of input is the image
	 */
	if( !(ref = vips_image_new_from_buffer( data + sizeof( mosaic_opt ),
		size - sizeof( mosaic_opt ), "", NULL )) )
		return( 0 );

	if( ref->Xsize > 100 ||
		ref->Ysize > 100 ||
		ref->Bands > 4 ) {
		g_object_unref( ref );
		return( 0 );
	}

	if( vips_rot180( ref, &sec, NULL ) ) {
		g_object_unref( ref );
		return( 0 );
	}

	if( vips_mosaic( ref, sec, &out, (VipsDirection) opt.dir,
		opt.xref, opt.yref, opt.xsec, opt.ysec, NULL ) ) {
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
