/* load a GIF with libnsgif
 *
 * 6/10/18
 * 	- from gifload.c
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VERBOSE
 */
#define VIPS_DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* TODO:
 *
 * - look into frame / page match up ... what about optimised GIFs where
 *   several frames make up each page?
 *
 * - early close
 *
 * - libnsgif does not seem to support comment metadata
 *
 * Notes:
 *
 * - hard to detect mono images -- local_colour_table in libnsgif is only set
 *   when we decode a frame, so we can't tell just from init whether any
 *   frames
 *
 * - don't bother detecting alpha -- if we can't detect RGB, alpha won't help
 *   much
 *
 */

#ifdef HAVE_LIBNSGIF

#include <libnsgif/libnsgif.h>

#define VIPS_TYPE_FOREIGN_LOAD_GIF (vips_foreign_load_gif_get_type())
#define VIPS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGif ))
#define VIPS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGifClass))
#define VIPS_IS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_IS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_FOREIGN_LOAD_GIF_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGifClass ))

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* The animation created by libnsgif.
	 */
	gif_animation *anim;

	/* The data/size pair we pass to libnsgif.
	 */
	unsigned char *data;
	size_t size;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

static const char *
vips_foreign_load_gif_errstr( gif_result result )
{
	switch( result ) {
		case GIF_WORKING:
		return( _( "Working" ) ); 

	case GIF_OK:
		return( _( "OK" ) ); 

	case GIF_INSUFFICIENT_FRAME_DATA:
		return( _( "Insufficient data to complete frame" ) ); 

	case GIF_FRAME_DATA_ERROR:
		return( _( "GIF frame data error" ) ); 

	case GIF_INSUFFICIENT_DATA:
		return( _( "Insufficient data to do anything" ) ); 

	case GIF_DATA_ERROR:
		return( _( "GIF header data error" ) ); 

	case GIF_INSUFFICIENT_MEMORY:
		return( _( "Insuficient memory to process" ) ); 

	case GIF_FRAME_NO_DISPLAY:
		return( _( "No display" ) ); 

	case GIF_END_OF_FRAME:
		return( _( "At end of frame" ) ); 

	default:
		return( _( "Unknown error" ) ); 
	}
}

static void
vips_foreign_load_gif_error( VipsForeignLoadGif *gif, gif_result result )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	vips_error( class->nickname, "%s", 
		vips_foreign_load_gif_errstr( result ) );
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_dispose:\n" );

	VIPS_FREEF( gif_finalise, gif->anim );

	G_OBJECT_CLASS( vips_foreign_load_gif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static gboolean
vips_foreign_load_gif_is_a_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_is_a_buffer:\n" );

	if( len >= 4 &&
		str[0] == 'G' && 
		str[1] == 'I' &&
		str[2] == 'F' &&
		str[3] == '8' )
		return( 1 );

	return( 0 );
}

static gboolean
vips_foreign_load_gif_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) == 4 &&
		vips_foreign_load_gif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static void *
vips_foreign_load_gif_bitmap_create( int width, int height )
{
        /* ensure a stupidly large bitmap is not created 
	 */

        return calloc(width * height, 4);
}

static void 
vips_foreign_load_gif_bitmap_set_opaque( void *bitmap, bool opaque )
{
        (void) opaque;  /* unused */
        (void) bitmap;  /* unused */
        g_assert(bitmap);
}

static bool 
vips_foreign_load_gif_bitmap_test_opaque( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert(bitmap);
        return false;
}

static unsigned char *
vips_foreign_load_gif_bitmap_get_buffer( void *bitmap )
{
        g_assert(bitmap);
        return bitmap;
}

static void 
vips_foreign_load_gif_bitmap_destroy( void *bitmap )
{
        g_assert(bitmap);
        free(bitmap);
}

static void 
vips_foreign_load_gif_bitmap_modified( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert(bitmap);
        return;
}

static gif_bitmap_callback_vt vips_foreign_load_gif_bitmap_callbacks = {
	vips_foreign_load_gif_bitmap_create,
	vips_foreign_load_gif_bitmap_destroy,
	vips_foreign_load_gif_bitmap_get_buffer,
	vips_foreign_load_gif_bitmap_set_opaque,
	vips_foreign_load_gif_bitmap_test_opaque,
	vips_foreign_load_gif_bitmap_modified
};

#ifdef VERBOSE
static void
print_frame( gif_frame *frame )
{
	printf( "frame:\n" );
	printf( "  display = %d\n", frame->display );
	printf( "  frame_delay = %d\n", frame->frame_delay );
	printf( "  virgin = %d\n", frame->virgin );
	printf( "  opaque = %d\n", frame->opaque );
	printf( "  redraw_required = %d\n", frame->redraw_required );
	printf( "  disposal_method = %d\n", frame->disposal_method );
	printf( "  transparency = %d\n", frame->transparency );
	printf( "  transparency_index = %d\n", frame->transparency_index );
	printf( "  redraw_x = %d\n", frame->redraw_x );
	printf( "  redraw_y = %d\n", frame->redraw_y );
	printf( "  redraw_width = %d\n", frame->redraw_width );
	printf( "  redraw_height = %d\n", frame->redraw_height );
}

static void
print_animation( gif_animation *anim )
{
	int i;

	printf( "animation:\n" );
	printf( "  width = %d\n", anim->width );
	printf( "  height = %d\n", anim->height );
	printf( "  frame_count = %d\n", anim->frame_count );
	printf( "  frame_count_partial = %d\n", anim->frame_count_partial );
	printf( "  decoded_frame = %d\n", anim->decoded_frame );
	printf( "  frame_image = %p\n", anim->frame_image );
	printf( "  loop_count = %d\n", anim->loop_count );
	printf( "  frame_holders = %d\n", anim->frame_holders );
	printf( "  background_index = %d\n", anim->background_index );
	printf( "  colour_table_size = %d\n", anim->colour_table_size );
	printf( "  global_colours = %d\n", anim->global_colours );
	printf( "  global_colour_table = %p\n", anim->global_colour_table );
	printf( "  local_colour_table = %p\n", anim->local_colour_table );

	for( i = 0; i < anim->frame_holders; i++ ) {
		printf( "%d ", i );
		print_frame( &anim->frames[i] );
	}
}
#endif /*VERBOSE*/

static int
vips_foreign_load_gif_set_header( VipsForeignLoadGif *gif, VipsImage *image )
{
	vips_image_init_fields( image,
		gif->anim->width, gif->anim->height * gif->n, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	vips_image_pipelinev( image, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	if( vips_object_argument_isset( VIPS_OBJECT( gif ), "n" ) )
		vips_image_set_int( image,
			VIPS_META_PAGE_HEIGHT, gif->anim->height );
	vips_image_set_int( image, VIPS_META_N_PAGES, gif->anim->frame_count );
	vips_image_set_int( image, "gif-loop", gif->anim->loop_count );

	/* The deprecated gif-delay field is in centiseconds.
	 */
	vips_image_set_int( image,
		"gif-delay", gif->anim->frames[0].frame_delay );

	/* TODO make and set the "delay" array in ms
		vips_image_set_array_int( image, 
			"delay", gif->delays, gif->n_pages );
	 */

	return( 0 );
}

/* Scan the GIF as quickly as we can and extract transparency, bands, pages,
 * etc.
 *
 * Don't flag any errors unless we have to: we want to work for corrupt or
 * malformed GIFs.
 */
static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	gif_result result;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_header:\n" );

	if( !(gif->anim = VIPS_NEW( load, gif_animation )) )
		return( -1 );
	gif_create( gif->anim, &vips_foreign_load_gif_bitmap_callbacks );

	/* GIF_INSUFFICIENT_FRAME_DATA means we allow truncated GIFs. 
	 *
	 * TODO use fail to bail out on truncated GIFs.
	 */
	result = gif_initialise( gif->anim, gif->size, gif->data );
	VIPS_DEBUG_MSG( "gif_initialise() = %d\n", result );
#ifdef VERBOSE
	print_animation( gif->anim );
#endif /*VERBOSE*/
	if( result != GIF_OK && 
		result != GIF_WORKING &&
		result != GIF_INSUFFICIENT_FRAME_DATA ) {
		vips_foreign_load_gif_error( gif, result ); 
		return( -1 );
	}
	if( !gif->anim->frame_count ) {
		vips_error( class->nickname, "%s", _( "no frames in GIF" ) );
		return( -1 );
	}

	if( gif->n == -1 )
		gif->n = gif->anim->frame_count - gif->page;

	if( gif->page < 0 ||
		gif->n <= 0 ||
		gif->page + gif->n > gif->anim->frame_count ) {
		vips_error( class->nickname, "%s", _( "bad page number" ) );
		return( -1 );
	}

	vips_foreign_load_gif_set_header( gif, load->out );

	return( 0 );
}

static int
vips_foreign_load_gif_generate( VipsRegion *or,
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) a;

	int y;

#ifdef VERBOSE
	VIPS_DEBUG_MSG( "vips_foreign_load_gif_generate: "
		"top = %d, height = %d\n", r->top, r->height );
#endif /*VERBOSE*/

	for( y = 0; y < r->height; y++ ) {
		/* The page for this output line, and the line number in page.
		 */
		int page = (r->top + y) / gif->anim->height + gif->page;
		int line = (r->top + y) % gif->anim->height;

		gif_result result;
		VipsPel *p, *q;

		g_assert( line >= 0 && line < gif->anim->height );
		g_assert( page >= 0 && page < gif->anim->frame_count );

		/* TODO 
		 *
		 * Do we need to loop to read earlier pages?
		 */
		if( gif->anim->decoded_frame != page ) {
			result = gif_decode_frame( gif->anim, page ); 
			VIPS_DEBUG_MSG( "  gif_decode_frame(%d) = %d\n", 
				page, result );
			if( result != GIF_OK ) {
				vips_foreign_load_gif_error( gif, result ); 
				return( -1 );
			}
#ifdef VERBOSE
			print_animation( gif->anim );
#endif /*VERBOSE*/
		}

		/* TODO ... handle G, GA, RGB cases as well.
		 */
		p = gif->anim->frame_image + 
			line * gif->anim->width * sizeof( int );
		q = VIPS_REGION_ADDR( or, 0, r->top + y );
		memcpy( q, p, VIPS_REGION_SIZEOF_LINE( or ) );
	}

	return( 0 );
}

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_load:\n" );

	/* Make the output pipeline.
	 */
	t[0] = vips_image_new();
	if( vips_foreign_load_gif_set_header( gif, t[0] ) )
		return( -1 );

	/* TODO 
	 *
	 * Close input immediately at end of read.
	g_signal_connect( t[0], "minimise", 
		G_CALLBACK( vips_foreign_load_gif_minimise ), gif ); 
	 */

	/* Strips 8 pixels high to avoid too many tiny regions.
	 */
	if( vips_image_generate( t[0],
		NULL, vips_foreign_load_gif_generate, NULL, gif, NULL ) ||
		vips_sequential( t[0], &t[1],
			"tile_height", VIPS__FATSTRIP_HEIGHT,
			NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_gif_class_init( VipsForeignLoadGifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_gif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_base";
	object_class->description = _( "load GIF with libnsgif" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;
	load_class->header = vips_foreign_load_gif_header;
	load_class->load = vips_foreign_load_gif_load;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 6,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, n ),
		-1, 100000, 1 );

}

static void
vips_foreign_load_gif_init( VipsForeignLoadGif *gif )
{
	gif->n = 1;
}

typedef struct _VipsForeignLoadGifFile {
	VipsForeignLoadGif parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* mmap here.
	 */
	int fd;
	void *base;
	gint64 length;

} VipsForeignLoadGifFile;

typedef VipsForeignLoadGifClass VipsForeignLoadGifFileClass;

G_DEFINE_TYPE( VipsForeignLoadGifFile, vips_foreign_load_gif_file, 
	vips_foreign_load_gif_get_type() );

static void
vips_foreign_load_gif_file_dispose( GObject *gobject )
{
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) gobject;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_file_dispose:\n" );

	G_OBJECT_CLASS( vips_foreign_load_gif_parent_class )->
		dispose( gobject );

	if( file->fd >= 0 ) {
		(void) g_close( file->fd, NULL );
		file->fd  = -1;
	}

	if( file->base ) {
		vips__munmap( file->base, file->length );
		file->base = NULL;
		file->length = 0;
	}
}

static int
vips_foreign_load_gif_file_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) load;

	struct stat st;
	mode_t m;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_file_header:\n" );

	/* Open and mmap the file.
	 */
	file->fd = vips__open_read( file->filename );
	if( file->fd == -1 ) {
		vips_error_system( errno, class->nickname, 
			_( "unable to open file \"%s\" for reading" ), 
			file->filename );
		return( -1 );
	}
	if( (file->length = vips_file_length( file->fd )) == -1 )
		return( -1 );

	if( fstat( file->fd, &st ) == -1 ) {
		vips_error( class->nickname, 
			"%s", _( "unable to get file status" ) );
		return( -1 );
	}
	m = (mode_t) st.st_mode;
	if( !S_ISREG( m ) ) {
		vips_error( class->nickname, 
			"%s", _( "not a regular file" ) ); 
		return( -1 ); 
	}

	if( !(file->base = vips__mmap( file->fd, 0, file->length, 0 )) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );
	gif->data = file->base;
	gif->size = file->length;

	return( VIPS_FOREIGN_LOAD_GIF_CLASS(
		vips_foreign_load_gif_file_parent_class )->header( load ) );
}

static const char *vips_foreign_gif_suffs[] = {
	".gif",
	NULL
};

static void
vips_foreign_load_gif_file_class_init( 
	VipsForeignLoadGifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_gif_file_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with libnsgif" );

	foreign_class->suffs = vips_foreign_gif_suffs;

	load_class->is_a = vips_foreign_load_gif_is_a;
	load_class->header = vips_foreign_load_gif_file_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadGifFile, filename ),
		NULL );

}

static void
vips_foreign_load_gif_file_init( VipsForeignLoadGifFile *file )
{
	file->fd = -1;
}

typedef struct _VipsForeignLoadGifBuffer {
	VipsForeignLoadGif parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

	/* Current read point, bytes left in buffer.
	 */
	VipsPel *p;
	size_t bytes_to_go;

} VipsForeignLoadGifBuffer;

typedef VipsForeignLoadGifClass VipsForeignLoadGifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadGifBuffer, vips_foreign_load_gif_buffer, 
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *) load;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_buffer_header:\n" );

	gif->data = buffer->buf->data;
	gif->size = buffer->buf->length;

	return( VIPS_FOREIGN_LOAD_GIF_CLASS(
		vips_foreign_load_gif_file_parent_class )->header( load ) );
}

static void
vips_foreign_load_gif_buffer_class_init( 
	VipsForeignLoadGifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_buffer";
	object_class->description = _( "load GIF with libnsgif" );

	load_class->is_a_buffer = vips_foreign_load_gif_is_a_buffer;
	load_class->header = vips_foreign_load_gif_buffer_header;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadGifBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_gif_buffer_init( VipsForeignLoadGifBuffer *buffer )
{
}

#endif /*HAVE_LIBNSGIF*/
