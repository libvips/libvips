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
#define VIPS_DEBUG
 */

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
 * - libnsgif does not seem to support comment metadata
 *
 * - it always loads the entire source file into memory
 *
 * Notes:
 *
 * - hard to detect mono images -- local_colour_table in libnsgif is only set
 *   when we decode a frame, so we can't tell just from init whether any
 *   frames have colour info
 *
 * - don't bother detecting alpha -- if we can't detect RGB, alpha won't help
 *   much
 *
 */

#ifdef HAVE_NSGIF

#include <libnsgif/libnsgif.h>

#define VIPS_TYPE_FOREIGN_LOAD_GIF (vips_foreign_load_nsgif_get_type())
#define VIPS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadNsgif ))
#define VIPS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadNsgifClass))
#define VIPS_IS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_IS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_FOREIGN_LOAD_GIF_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadNsgifClass ))

typedef struct _VipsForeignLoadNsgif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* Load from this source (set by subclasses).
	 */
	VipsSource *source;

	/* The animation created by libnsgif.
	 */
	gif_animation *anim;

	/* The data/size pair we pass to libnsgif.
	 */
	unsigned char *data;
	size_t size;

	/* The frame_count, after we have removed undisplayable frames.
	 */
	int frame_count_displayable;

	/* Delays between frames (in milliseconds). Array of length 
	 * @frame_count_displayable.
	 */
	int *delay;

	/* A single centisecond value for compatibility.
	 */
	int gif_delay;

	/* If the GIF contains any frames with transparent elements.
	 */
	gboolean has_transparency;

} VipsForeignLoadNsgif;

typedef VipsForeignLoadClass VipsForeignLoadNsgifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadNsgif, vips_foreign_load_nsgif, 
	VIPS_TYPE_FOREIGN_LOAD );

static const char *
vips_foreign_load_nsgif_errstr( gif_result result )
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
vips_foreign_load_nsgif_error( VipsForeignLoadNsgif *gif, gif_result result )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	vips_error( class->nickname, "%s", 
		vips_foreign_load_nsgif_errstr( result ) );
}

static void
vips_foreign_load_nsgif_dispose( GObject *gobject )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) gobject;

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_dispose:\n" );

	if( gif->anim ) {
		gif_finalise( gif->anim );
		VIPS_FREE( gif->anim );
	}
	VIPS_UNREF( gif->source );
	VIPS_FREE( gif->delay );

	G_OBJECT_CLASS( vips_foreign_load_nsgif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_nsgif_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static VipsForeignFlags
vips_foreign_load_nsgif_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static gboolean
vips_foreign_load_nsgif_is_a_source( VipsSource *source )
{
	const unsigned char *data;

	if( (data = vips_source_sniff( source, 4 )) &&
		data[0] == 'G' &&
		data[1] == 'I' &&
		data[2] == 'F' &&
		data[3] == '8' )
		return( TRUE );

	return( FALSE );
}

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
vips_foreign_load_nsgif_set_header( VipsForeignLoadNsgif *gif, 
	VipsImage *image )
{
	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_set_header:\n" );

	vips_image_init_fields( image,
		gif->anim->width, gif->anim->height * gif->n, 
		gif->has_transparency ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	vips_image_pipelinev( image, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	if( vips_object_argument_isset( VIPS_OBJECT( gif ), "n" ) )
		vips_image_set_int( image,
			VIPS_META_PAGE_HEIGHT, gif->anim->height );
	vips_image_set_int( image, VIPS_META_N_PAGES, 
		gif->frame_count_displayable );
	vips_image_set_int( image, "loop", gif->anim->loop_count );
	vips_image_set_array_int( image, "delay", 
		gif->delay, gif->frame_count_displayable );

	if( gif->anim->global_colours &&
		gif->anim->global_colour_table &&
		gif->anim->background_index >= 0 &&
		gif->anim->background_index < gif->anim->colour_table_size ) {
		int index = gif->anim->background_index;
		unsigned char *entry = (unsigned char *) 
			&gif->anim->global_colour_table[index];

		double array[3];

		array[0] = entry[0];
		array[1] = entry[1];
		array[2] = entry[2];

		vips_image_set_array_double( image, "background", array, 3 );
	}

	VIPS_SETSTR( image->filename, 
		vips_connection_filename( VIPS_CONNECTION( gif->source ) ) );

	/* DEPRECATED "gif-loop"
	 *
	 * Not the correct behavior as loop=1 became gif-loop=0
	 * but we want to keep the old behavior untouched!
	 */
	vips_image_set_int( image,
		"gif-loop", gif->anim->loop_count == 0 ? 
			0 : gif->anim->loop_count - 1 );

	/* The deprecated gif-delay field is in centiseconds.
	 */
	vips_image_set_int( image, "gif-delay", gif->gif_delay ); 

	return( 0 );
}

/* Scan the GIF as quickly as we can and extract transparency, bands, pages,
 * etc.
 *
 * Don't flag any errors unless we have to: we want to work for corrupt or
 * malformed GIFs.
 *
 * Close as soon as we can to free up the fd.
 */
static int
vips_foreign_load_nsgif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) load;

	const void *data;
	size_t size;
	gif_result result;
	int i;

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_header:\n" );

	/* We map in the image, then minimise to close any underlying file
	 * object. This won't unmap.
	 */
	if( !(data = vips_source_map( gif->source, &size )) ) 
		return( -1 );
	vips_source_minimise( gif->source );

	result = gif_initialise( gif->anim, size, (void *) data );
	VIPS_DEBUG_MSG( "gif_initialise() = %d\n", result );
#ifdef VERBOSE
	print_animation( gif->anim );
#endif /*VERBOSE*/
	if( result != GIF_OK && 
		result != GIF_WORKING &&
		result != GIF_INSUFFICIENT_FRAME_DATA ) {
		vips_foreign_load_nsgif_error( gif, result ); 
		return( -1 );
	}
	else if( result == GIF_INSUFFICIENT_FRAME_DATA &&
		load->fail ) {
		vips_error( class->nickname, "%s", _( "truncated GIF" ) );
		return( -1 );
	}

	/* Many GIFs have dead frames at the end. Remove these from our count.
	 */
	for( i = gif->anim->frame_count - 1; 
		i >= 0 && !gif->anim->frames[i].display; i-- ) 
		;
	gif->frame_count_displayable = i + 1;
#ifdef VERBOSE
	if( gif->frame_count_displayable != gif->anim->frame_count )
		printf( "vips_foreign_load_nsgif_open: "
			"removed %d undisplayable frames\n", 
			gif->anim->frame_count - gif->frame_count_displayable );
#endif /*VERBOSE*/

	if( !gif->frame_count_displayable ) {
		vips_error( class->nickname, "%s", _( "no frames in GIF" ) );
		return( -1 );
	}

	/* Check for any transparency.
	 */
	for( i = 0; i < gif->frame_count_displayable; i++ ) 
		if( gif->anim->frames[i].transparency ) {
			gif->has_transparency = TRUE;
			break;
		}

	if( gif->n == -1 )
		gif->n = gif->frame_count_displayable - gif->page;

	if( gif->page < 0 ||
		gif->n <= 0 ||
		gif->page + gif->n > gif->frame_count_displayable ) {
		vips_error( class->nickname, "%s", _( "bad page number" ) );
		return( -1 );
	}

	/* In ms, frame_delay in cs.
	 */
	VIPS_FREE( gif->delay );
	if( !(gif->delay = VIPS_ARRAY( NULL, 
		gif->frame_count_displayable, int )) )
		return( -1 );
	for( i = 0; i < gif->frame_count_displayable; i++ )
		gif->delay[i] = 10 * gif->anim->frames[i].frame_delay;

	gif->gif_delay = gif->anim->frames[0].frame_delay;

	vips_foreign_load_nsgif_set_header( gif, load->out );

	return( 0 );
}

static int
vips_foreign_load_nsgif_generate( VipsRegion *or,
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) a;

	int y;

#ifdef VERBOSE
	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_generate: "
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
		g_assert( page >= 0 && page < gif->frame_count_displayable );

		if( gif->anim->decoded_frame != page ) {
			result = gif_decode_frame( gif->anim, page ); 
			VIPS_DEBUG_MSG( "  gif_decode_frame(%d) = %d\n", 
				page, result );
			if( result != GIF_OK ) {
				vips_foreign_load_nsgif_error( gif, result ); 
				return( -1 );
			}
#ifdef VERBOSE
			print_animation( gif->anim );
#endif /*VERBOSE*/
		}

		p = gif->anim->frame_image + 
			line * gif->anim->width * sizeof( int );
		q = VIPS_REGION_ADDR( or, 0, r->top + y );
		if( gif->has_transparency )
			memcpy( q, p, VIPS_REGION_SIZEOF_LINE( or ) );
		else {
			int i;

			for( i = 0; i < r->width; i++ ) {
				q[0] = p[0];
				q[1] = p[1];
				q[2] = p[2];

				q += 3;
				p += 4;
			}
		}
	}

	return( 0 );
}

static int
vips_foreign_load_nsgif_load( VipsForeignLoad *load )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) load;
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_load:\n" );

	/* Make the output pipeline.
	 */
	t[0] = vips_image_new();
	if( vips_foreign_load_nsgif_set_header( gif, t[0] ) )
		return( -1 );

	/* Strips 8 pixels high to avoid too many tiny regions.
	 */
	if( vips_image_generate( t[0],
		NULL, vips_foreign_load_nsgif_generate, NULL, gif, NULL ) ||
		vips_sequential( t[0], &t[1],
			"tile_height", VIPS__FATSTRIP_HEIGHT,
			NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_nsgif_class_init( VipsForeignLoadNsgifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_nsgif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_base";
	object_class->description = _( "load GIF with libnsgif" );

	/* High priority, so that we handle vipsheader etc.
	 */
	foreign_class->priority = 50;

	load_class->get_flags_filename = 
		vips_foreign_load_nsgif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_nsgif_get_flags;
	load_class->header = vips_foreign_load_nsgif_header;
	load_class->load = vips_foreign_load_nsgif_load;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadNsgif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 6,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadNsgif, n ),
		-1, 100000, 1 );

}

static void *
vips_foreign_load_nsgif_bitmap_create( int width, int height )
{
	/* Enforce max GIF dimensions of 16383 (0x7FFF). This should be enough
	 * for anyone, and will prevent the worst GIF bombs.
	 */
	if( width <= 0 ||
		width > 16383 ||
		height <= 0 ||
		height > 16383 ) {
		vips_error( "gifload",
			"%s", _( "bad image dimensions") );
		return( NULL );
	}

	return g_malloc0( (gsize) width * height * 4 );
}

static void 
vips_foreign_load_nsgif_bitmap_set_opaque( void *bitmap, bool opaque )
{
        (void) opaque;  /* unused */
        (void) bitmap;  /* unused */
        g_assert( bitmap );
}

static bool 
vips_foreign_load_nsgif_bitmap_test_opaque( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert( bitmap );

        return( false );
}

static unsigned char *
vips_foreign_load_nsgif_bitmap_get_buffer( void *bitmap )
{
        g_assert( bitmap );

        return( bitmap );
}

static void 
vips_foreign_load_nsgif_bitmap_destroy( void *bitmap )
{
        g_assert( bitmap );
        g_free( bitmap );
}

static void 
vips_foreign_load_nsgif_bitmap_modified( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert( bitmap );

        return;
}

static gif_bitmap_callback_vt vips_foreign_load_nsgif_bitmap_callbacks = {
	vips_foreign_load_nsgif_bitmap_create,
	vips_foreign_load_nsgif_bitmap_destroy,
	vips_foreign_load_nsgif_bitmap_get_buffer,
	vips_foreign_load_nsgif_bitmap_set_opaque,
	vips_foreign_load_nsgif_bitmap_test_opaque,
	vips_foreign_load_nsgif_bitmap_modified
};

static void
vips_foreign_load_nsgif_init( VipsForeignLoadNsgif *gif )
{
	gif->anim = g_new0( gif_animation, 1 );
	gif_create( gif->anim, &vips_foreign_load_nsgif_bitmap_callbacks );
	gif->n = 1;
}

typedef struct _VipsForeignLoadNsgifFile {
	VipsForeignLoadNsgif parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadNsgifFile;

typedef VipsForeignLoadNsgifClass VipsForeignLoadNsgifFileClass;

G_DEFINE_TYPE( VipsForeignLoadNsgifFile, vips_foreign_load_nsgif_file, 
	vips_foreign_load_nsgif_get_type() );

static int
vips_foreign_load_gif_file_build( VipsObject *object )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) object;
	VipsForeignLoadNsgifFile *file = (VipsForeignLoadNsgifFile *) object;

	if( file->filename )
		if( !(gif->source =
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_nsgif_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_nsgif_suffs[] = {
	".gif",
	NULL
};

static gboolean
vips_foreign_load_nsgif_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_nsgif_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_nsgif_file_class_init( 
	VipsForeignLoadNsgifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with libnsgif" );
	object_class->build = vips_foreign_load_gif_file_build;

	foreign_class->suffs = vips_foreign_nsgif_suffs;

	load_class->is_a = vips_foreign_load_nsgif_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNsgifFile, filename ),
		NULL );

}

static void
vips_foreign_load_nsgif_file_init( VipsForeignLoadNsgifFile *file )
{
}

typedef struct _VipsForeignLoadNsgifBuffer {
	VipsForeignLoadNsgif parent_object;

	/* Load from a buffer.
	 */
	VipsArea *blob;

} VipsForeignLoadNsgifBuffer;

typedef VipsForeignLoadNsgifClass VipsForeignLoadNsgifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadNsgifBuffer, vips_foreign_load_nsgif_buffer, 
	vips_foreign_load_nsgif_get_type() );

static int
vips_foreign_load_nsgif_buffer_build( VipsObject *object )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) object;
	VipsForeignLoadNsgifBuffer *buffer = 
		(VipsForeignLoadNsgifBuffer *) object;

	if( buffer->blob &&
		!(gif->source = vips_source_new_from_memory( 
			buffer->blob->data, 
			buffer->blob->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_nsgif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_nsgif_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_nsgif_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_nsgif_buffer_class_init( 
	VipsForeignLoadNsgifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_buffer";
	object_class->description = _( "load GIF with libnsgif" );
	object_class->build = vips_foreign_load_nsgif_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_nsgif_buffer_is_a_buffer;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNsgifBuffer, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_nsgif_buffer_init( VipsForeignLoadNsgifBuffer *buffer )
{
}

typedef struct _VipsForeignLoadNsgifSource {
	VipsForeignLoadNsgif parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadNsgifSource;

typedef VipsForeignLoadClass VipsForeignLoadNsgifSourceClass;

G_DEFINE_TYPE( VipsForeignLoadNsgifSource, vips_foreign_load_nsgif_source, 
	vips_foreign_load_nsgif_get_type() );

static int
vips_foreign_load_nsgif_source_build( VipsObject *object )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) object;
	VipsForeignLoadNsgifSource *source = 
		(VipsForeignLoadNsgifSource *) object;

	if( source->source ) {
		gif->source = source->source;
		g_object_ref( gif->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_nsgif_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_nsgif_source_class_init( 
	VipsForeignLoadNsgifSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_source";
	object_class->description = _( "load gif from source" );
	object_class->build = vips_foreign_load_nsgif_source_build;

	load_class->is_a_source = vips_foreign_load_nsgif_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNsgifSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_nsgif_source_init( VipsForeignLoadNsgifSource *source )
{
}

#endif /*HAVE_NSGIF*/

/**
 * vips_gifload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Read a GIF file into a libvips image.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column. Set to -1 to mean "until the end of the
 * document". Use vips_grid() to change page layout.
 *
 * The output image is RGBA for GIFs containing transparent elements, RGB
 * otherwise.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gifload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_gifload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Read a GIF-formatted memory block into a VIPS image. Exactly as
 * vips_gifload(), but read from a memory buffer.
 *
 * You must not free the buffer while @out is active. The
 * #VipsObject::postclose signal on @out is a good place to free.
 *
 * See also: vips_gifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "gifload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_gifload_source:
 * @source: source to load
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Exactly as vips_gifload(), but read from a source.
 *
 * See also: vips_gifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gifload_source", ap, source, out );
	va_end( ap );

	return( result );
}
