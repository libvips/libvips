/* Test stream*u.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <vips/vips.h>

typedef struct _MyInput {
	const char *filename; 
	unsigned char *contents; 
	size_t length;
	size_t read_position;
} MyInput;

typedef struct _MyOutput {
	const char *filename; 
	int fd;
} MyOutput;

static gint64
read_cb( VipsSourceCustom *source_custom, 
	void *buffer, gint64 length, MyInput *my_input )
{
	gint64 bytes_read = VIPS_MIN( length, 
		my_input->length - my_input->read_position );

	/*
	printf( "read_cb: buffer = 0x%p, length = %zd\n", buffer, length );
	 */

	memcpy( buffer, 
		my_input->contents + my_input->read_position, bytes_read );
	my_input->read_position += bytes_read;

	return( bytes_read );
}

static gint64
seek_cb( VipsSourceCustom *source_custom, 
	gint64 offset, int whence, MyInput *my_input )
{
	gint64 new_pos;

	/*
	printf( "seek_cb: offset = %zd, whence = %d\n", offset, whence );
	 */

	switch( whence ) {
	case SEEK_SET:
		new_pos = offset;
		break;

	case SEEK_CUR:
		new_pos = my_input->read_position + offset;
		break;

	case SEEK_END:
		new_pos = my_input->length + offset;
		break;

	default:
		vips_error( "demo", "%s", "bad 'whence'" );
		return( -1 );
	}

	my_input->read_position = VIPS_CLIP( 0, new_pos, my_input->length );

	return( my_input->read_position );
}

static gint64
write_cb( VipsTargetCustom *target_custom, 
	const void *data, gint64 length, MyOutput *my_output )
{
	gint64 bytes_written;

	/*
	printf( "write_cb: data = 0x%p, length = %zd\n", data, length );
	 */

	bytes_written = write( my_output->fd, data, length );

	return( bytes_written );
}

static void
finish_cb( VipsTargetCustom *target_custom, MyOutput *my_output ) 
{
	/*
	printf( "finish_cb:\n" );
	 */

	close( my_output->fd );
	my_output->fd = -1;
}

int
main( int argc, char **argv )
{
	MyInput my_input;
	MyOutput my_output;
	VipsSourceCustom *source_custom;
	VipsTargetCustom *target_custom;
	VipsImage *image;

	if( VIPS_INIT( argv[0] ) )
		return( -1 );

	if( argc != 3 ) 
		vips_error_exit( "usage: %s in-file out-file.png", argv[0] );

	my_input.filename = argv[1];
	my_input.contents = NULL;
	my_input.length = 0;
	my_input.read_position = 0;

	if( !g_file_get_contents( my_input.filename, 
		(char **) &my_input.contents, &my_input.length, NULL ) ) 
		vips_error_exit( "unable to load from %s", my_input.filename );

	source_custom = vips_source_custom_new();
	g_signal_connect( source_custom, "seek", 
		G_CALLBACK( seek_cb ), &my_input );
	g_signal_connect( source_custom, "read", 
		G_CALLBACK( read_cb ), &my_input );

	if( !(image = vips_image_new_from_source( 
		VIPS_SOURCE( source_custom ), "",
		"access", VIPS_ACCESS_SEQUENTIAL,
		NULL )) ) 
		vips_error_exit( NULL );

	my_output.filename = argv[2];
	my_output.fd = -1;

	if( (my_output.fd = vips__open( my_output.filename, 
		O_WRONLY | O_CREAT | O_TRUNC, 0644 )) == -1 )
		vips_error_exit( "unable to save to %s", my_output.filename );

	target_custom = vips_target_custom_new();
	g_signal_connect( target_custom, "write",
		G_CALLBACK( write_cb ), &my_output );
	g_signal_connect( target_custom, "finish", 
		G_CALLBACK( finish_cb ), &my_output );

	if( vips_image_write_to_target( image, ".png", 
		VIPS_TARGET( target_custom ), NULL ) ) 
		vips_error_exit( NULL );

	VIPS_UNREF( image );
	VIPS_UNREF( source_custom );
	VIPS_UNREF( target_custom );
	g_free( my_input.contents );

	return( 0 );
}
