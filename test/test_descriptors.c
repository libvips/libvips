/* Read an image and check that file handles are being closed on minimise.
 *
 * This will only work on linux: we signal success and do nothing if /dev/proc
 * does not exist.
 */

#include <sys/types.h>
#include <unistd.h>

#include <vips/vips.h>

/* Count the number of files in a directory, -1 for directory not found etc.
 */
static int
count_files( const char *dirname )
{
	GDir *dir;
	int n;

	if( !(dir = g_dir_open( dirname, 0, NULL )) )
		return( -1 );

	for( n = 0; g_dir_read_name( dir ); n++ )
		;

	g_dir_close( dir );

	return( n );
}

int
main( int argc, char **argv )
{
	VipsImage *image, *x;
	char fd_dir[256];
	int n_files;
	double average;

        if( VIPS_INIT( argv[0] ) )
                vips_error_exit( "unable to start" ); 

	vips_snprintf( fd_dir, 256, "/proc/%d/fd", getpid() );
	n_files = count_files( fd_dir );
	if( n_files == -1 )
		/* Probably not linux, silent success.
		 */
		return( 0 );

	/* This is usually 4. stdout / stdin / stderr plus one more made for
	 * us by glib, I think, doing what I don't know.
	 */

	/* Opening an image should read the header, then close the fd.
	 */
	if( !(image = vips_image_new_from_file( argv[1], 
		"access", VIPS_ACCESS_SEQUENTIAL,
		NULL )) )
		vips_error_exit( NULL );
	if( count_files( fd_dir ) != n_files )
		vips_error_exit( "fd not closed after header read" );

	/* We should be able to read a chunk near the top, then have the fd
	 * closed again.
	 */
	if( vips_crop( image, &x, 0, 0, image->Xsize, 10, NULL ) ||
		vips_avg( x, &average, NULL ) )
		vips_error_exit( NULL );
	g_object_unref( x );
	if( count_files( fd_dir ) != n_files )
		vips_error_exit( "fd not closed after first read" );

	/* We should be able to read again, a little further down, and have
	 * the input restarted and closed again.
	 */
	if( vips_crop( image, &x, 0, 20, image->Xsize, 10, NULL ) ||
		vips_avg( x, &average, NULL ) )
		vips_error_exit( NULL );
	g_object_unref( x );
	if( count_files( fd_dir ) != n_files )
		vips_error_exit( "fd not closed after second read" );

	/* Clean up, and we should still just have three open.
	 */
	g_object_unref( x );
	vips_shutdown();

	if( count_files( fd_dir ) != n_files )
		vips_error_exit( "fd not closed after shutdown" );

	return( 0 );
}
