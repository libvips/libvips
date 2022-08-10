/* load a GIF with libnsgif
 *
 * 6/10/18
 * 	- from gifload.c
 * 3/3/22 tlsa
 *	- update libnsgif API
 *9/5/22
 	- attach GIF palette as metadata
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
#include <glib/gi18n-lib.h>

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
 */

#ifdef HAVE_NSGIF

#include <libnsgif/nsgif.h>

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
	nsgif_t *anim;

	/* The data/size pair we pass to libnsgif.
	 */
	unsigned char *data;
	size_t size;

	/* Information about the current GIF.
	 */
	const nsgif_info_t *info;

	/* Delays between frames (in milliseconds). Array of length 
	 * @info->frame_count.
	 */
	int *delay;

	/* A single centisecond value for compatibility.
	 */
	int gif_delay;

	/* If the GIF contains any frames with transparent elements.
	 */
	gboolean has_transparency;

	/* If the GIF has any local palettes.
	 */
	gboolean local_palette;

	/* The current frame bitmap and the frame number for it.
	 */
	nsgif_bitmap_t *bitmap;
	int frame_number;

} VipsForeignLoadNsgif;

typedef VipsForeignLoadClass VipsForeignLoadNsgifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadNsgif, vips_foreign_load_nsgif, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_nsgif_error( VipsForeignLoadNsgif *gif, nsgif_error result )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	vips_error( class->nickname, "%s", nsgif_strerror( result ) );
}

static void
vips_foreign_load_nsgif_dispose( GObject *gobject )
{
	VipsForeignLoadNsgif *gif = (VipsForeignLoadNsgif *) gobject;

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_dispose:\n" );

	if( gif->anim ) {
		nsgif_destroy( gif->anim );
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
print_frame( const nsgif_frame_info_t *frame_info )
{
	if ( frame_info == NULL )
		return;

	printf( "frame_info:\n" );
	printf( "  display = %d\n", frame_info->display );
	printf( "  local_palette = %d\n", frame_info->local_palette );
	printf( "  transparency = %d\n", frame_info->transparency );
	printf( "  disposal = %d (%s)\n", 
		frame_info->disposal, 
		nsgif_str_disposal( frame_info->disposal ) );
	printf( "  delay = %d\n", frame_info->delay );
	printf( "  rect.x0 = %u\n", frame_info->rect.x0 );
	printf( "  rect.y0 = %u\n", frame_info->rect.y0 );
	printf( "  rect.x1 = %u\n", frame_info->rect.x1 );
	printf( "  rect.y1 = %u\n", frame_info->rect.y1 );
}

static void
print_animation( nsgif_t *anim, const nsgif_info_t *info )
{
	int i;
	const uint8_t *bg = (uint8_t *) &info->background;

	printf( "animation:\n" );
	printf( "  width = %d\n", info->width );
	printf( "  height = %d\n", info->height );
	printf( "  frame_count = %d\n", info->frame_count );
	printf( "  global_palette = %d\n", info->global_palette );
	printf( "  loop_max = %d\n", info->loop_max );
	printf( "  background = %d %d %d %d\n",
		bg[0], bg[1], bg[2], bg[3] );

	for( i = 0; i < info->frame_count; i++ ) {
		printf( "%d ", i );
		print_frame( nsgif_get_frame_info( anim, i ) );
	}
}

#endif /*VERBOSE*/

static int
vips_foreign_load_nsgif_set_header( VipsForeignLoadNsgif *gif, 
	VipsImage *image )
{
	double array[3];
	const uint8_t *bg;
	size_t entries;
	uint32_t table[NSGIF_MAX_COLOURS];
	int colours;

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_set_header:\n" );

	vips_image_init_fields( image,
		gif->info->width, gif->info->height * gif->n,
		gif->has_transparency ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	vips_image_pipelinev( image, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	/* Only set page-height if we have more than one page, or this could
	 * accidentally turn into an animated image later.
	 */
	if( gif->n > 1 )
		vips_image_set_int( image,
			VIPS_META_PAGE_HEIGHT, gif->info->height );
	vips_image_set_int( image, VIPS_META_N_PAGES, 
		gif->info->frame_count );
	vips_image_set_int( image, "loop", gif->info->loop_max );

	vips_image_set_array_int( image, "delay", 
		gif->delay, gif->info->frame_count );


	bg = (uint8_t *) &gif->info->background;
	array[0] = bg[0];
	array[1] = bg[1];
	array[2] = bg[2];

	vips_image_set_array_double( image, "background", array, 3 );

	VIPS_SETSTR( image->filename, 
		vips_connection_filename( VIPS_CONNECTION( gif->source ) ) );

	/* DEPRECATED "gif-loop"
	 *
	 * Not the correct behavior as loop=1 became gif-loop=0
	 * but we want to keep the old behavior untouched!
	 */
	vips_image_set_int( image,
		"gif-loop", gif->info->loop_max == 0 ? 
			0 : gif->info->loop_max - 1 );

	/* The deprecated gif-delay field is in centiseconds.
	 */
	vips_image_set_int( image, "gif-delay", gif->gif_delay ); 

	/* If there are no local palettes, we can attach the global palette as
	 * metadata.
	 */
	if( !gif->local_palette ) {
		nsgif_global_palette( gif->anim, table, &entries );
		vips_image_set_array_int( image, "gif-palette", 
			(const int *) table, entries );

		colours = entries;
	} 
	else {
		int i;

		colours = 0;

		if( gif->info->global_palette ) {
			nsgif_global_palette( gif->anim, table, &entries );
			colours = entries;
		}

		for( i = 0; i < gif->info->frame_count; i++ ) {
			if( nsgif_local_palette( gif->anim, i, table,
				&entries ) ) 
				colours = VIPS_MAX( colours, entries );
		}
	}

	vips_image_set_int( image, "palette-bit-depth", 
		ceil( log2( colours ) ) ); 

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
	nsgif_error result;
	int i;

	VIPS_DEBUG_MSG( "vips_foreign_load_nsgif_header:\n" );

	/* We map in the image, then minimise to close any underlying file
	 * object. This won't unmap.
	 */
	if( !(data = vips_source_map( gif->source, &size )) ) 
		return( -1 );
	vips_source_minimise( gif->source );

	result = nsgif_data_scan( gif->anim, size, (void *) data );
	VIPS_DEBUG_MSG( "nsgif_data_scan() = %s\n", nsgif_strerror( result ) );
	gif->info = nsgif_get_info(gif->anim);
#ifdef VERBOSE
	print_animation( gif->anim, gif->info );
#endif /*VERBOSE*/
	if( result != NSGIF_OK &&
		load->fail_on >= VIPS_FAIL_ON_WARNING ) {
		vips_foreign_load_nsgif_error( gif, result ); 
		return( -1 );
	}

	if( !gif->info->frame_count ) {
		vips_error( class->nickname, "%s", _( "no frames in GIF" ) );
		return( -1 );
	}

	/* Check for any transparency.
	 */
	for( i = 0; i < gif->info->frame_count; i++ ) {
		const nsgif_frame_info_t *frame_info;

		if( (frame_info = nsgif_get_frame_info( gif->anim, i )) ) {
			if( frame_info->transparency ) 
				gif->has_transparency = TRUE;
			if( frame_info->local_palette ) 
				gif->local_palette = TRUE;
		}
	}

	if( gif->n == -1 )
		gif->n = gif->info->frame_count - gif->page;

	if( gif->page < 0 ||
		gif->n <= 0 ||
		gif->page + gif->n > gif->info->frame_count ) {
		vips_error( class->nickname, "%s", _( "bad page number" ) );
		return( -1 );
	}

	/* In ms, frame_delay in cs.
	 */
	VIPS_FREE( gif->delay );
	if( !(gif->delay = VIPS_ARRAY( NULL, 
		gif->info->frame_count, int )) )
		return( -1 );
	for( i = 0; i < gif->info->frame_count; i++ ) {
		const nsgif_frame_info_t *frame_info;

		frame_info = nsgif_get_frame_info( gif->anim, i );
		if ( frame_info == NULL ) {
			vips_error( class->nickname, "%s", _( "bad frame" ) );
			return( -1 );
		}
		gif->delay[i] = 10 * frame_info->delay;
	}

	gif->gif_delay = gif->delay[0] / 10;

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
		int page = (r->top + y) / gif->info->height + gif->page;
		int line = (r->top + y) % gif->info->height;

		nsgif_error result;
		VipsPel *p, *q;

		g_assert( line >= 0 && line < gif->info->height );
		g_assert( page >= 0 && page < gif->info->frame_count );

		if( gif->frame_number != page ) {
			result = nsgif_frame_decode( gif->anim, 
				page, &gif->bitmap );
			VIPS_DEBUG_MSG( "  nsgif_frame_decode(%d) = %d\n",
				page, result );
			if( result != NSGIF_OK ) {
				vips_foreign_load_nsgif_error( gif, result );
				return( -1 );
			}

#ifdef VERBOSE
			print_frame( nsgif_get_frame_info( gif->anim, page ) );
#endif /*VERBOSE*/

			gif->frame_number = page;
		}

		p = gif->bitmap + line * gif->info->width * sizeof( int );
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
		_( "First page to load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadNsgif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 6,
		_( "n" ),
		_( "Number of pages to load, -1 for all" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadNsgif, n ),
		-1, 100000, 1 );

}

static void *
vips_foreign_load_nsgif_bitmap_create( int width, int height )
{
	/* GIF has a limit of 64k per axis -- double-check this.
	 */
	if( width <= 0 ||
		width > 65536 ||
		height <= 0 ||
		height > 65536 ) {
		vips_error( "gifload",
			"%s", _( "bad image dimensions") );
		return( NULL );
	}

	return g_malloc0( (gsize) width * height * 4 );
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

static nsgif_bitmap_cb_vt vips_foreign_load_nsgif_bitmap_callbacks = {
	vips_foreign_load_nsgif_bitmap_create,
	vips_foreign_load_nsgif_bitmap_destroy,
	vips_foreign_load_nsgif_bitmap_get_buffer,
};

static void
vips_foreign_load_nsgif_init( VipsForeignLoadNsgif *gif )
{
	nsgif_error result = nsgif_create(
		&vips_foreign_load_nsgif_bitmap_callbacks,
		NSGIF_BITMAP_FMT_R8G8B8A8,
		&gif->anim );
	if (result != NSGIF_OK) {
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
		vips_error( class->nickname, "%s",
			nsgif_strerror( result ) );
		return;
	}

	gif->n = 1;
	gif->frame_number = -1;
	gif->bitmap = NULL;
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
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_source";
	object_class->description = _( "load gif from source" );
	object_class->build = vips_foreign_load_nsgif_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

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
 * * @fail_on: #VipsFailOn, types of read error to fail on
 *
 * Read a GIF file into a libvips image.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column. Set to -1 to mean "until the end of the
 * document". Use vips_grid() to change page layout.
 *
 * Use @fail_on to set the type of error that will cause load to fail. By
 * default, loaders are permissive, that is, #VIPS_FAIL_ON_NONE.
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
 * * @fail_on: #VipsFailOn, types of read error to fail on
 *
 * Exactly as vips_gifload(), but read from a memory buffer.
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
 * * @fail_on: #VipsFailOn, types of read error to fail on
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
