/* load a GIF with giflib
 *
 * 10/2/16
 * 	- from svgload.c
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_GIFLIB

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include <gif_lib.h>

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	GifFileType *file;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

/* From gif2rgb.c ... offsets and jumps for interlaced GIF images.
 */
static int 
	InterlacedOffset[] = { 0, 4, 2, 1 },
	InterlacedJumps[] = { 8, 8, 4, 2 };

/* From ungif.h ... the locations of the transparency, repeat and delay
 * flags.
 */
#define GIF_GCE_DELAY_BYTE_LOW  1
#define GIF_GCE_DELAY_BYTE_HIGH 2
#define GIF_GCE_TRANSPARENCY_BYTE   3
#define GIF_NETSCAPE_REPEAT_BYTE_LOW    1
#define GIF_NETSCAPE_REPEAT_BYTE_HIGH   2

/* From gif-lib.h
 */
static const char *
vips_foreign_load_gif_errstr( int error_code )
{
	switch( error_code ) {
	case D_GIF_ERR_OPEN_FAILED:
		return( _( "Failed to open given file" ) ); 

	case D_GIF_ERR_READ_FAILED:
		return( _( "Failed to read from given file" ) ); 

	case D_GIF_ERR_NOT_GIF_FILE:
		return( _( "Data is not a GIF file" ) ); 

	case D_GIF_ERR_NO_SCRN_DSCR:
		return( _( "No screen descriptor detected" ) ); 

	case D_GIF_ERR_NO_IMAG_DSCR:
		return( _( "No image descriptor detected" ) ); 

	case D_GIF_ERR_NO_COLOR_MAP:
		return( _( "Neither global nor local color map" ) ); 

	case D_GIF_ERR_WRONG_RECORD:
		return( _( "Wrong record type detected" ) ); 

	case D_GIF_ERR_DATA_TOO_BIG:
		return( _( "Number of pixels bigger than width * height" ) ); 

	case D_GIF_ERR_NOT_ENOUGH_MEM:
		return( _( "Failed to allocate required memory" ) ); 

	case D_GIF_ERR_CLOSE_FAILED:
		return( _( "Failed to close given file" ) ); 

	case D_GIF_ERR_NOT_READABLE:
		return( _( "Given file was not opened for read" ) ); 

	case D_GIF_ERR_IMAGE_DEFECT:
		return( _( "Image is defective, decoding aborted" ) ); 

	case D_GIF_ERR_EOF_TOO_SOON:
		return( _( "Image EOF detected, before image complete" ) ); 

	default:
		return( _( "Unknown error" ) ); 
	}
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_FREEF( DGifCloseFile, gif->file );

	G_OBJECT_CLASS( vips_foreign_load_gif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags_filename( const char *filename )
{
	/* We can render any part of the image on demand.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static gboolean
vips_foreign_load_gif_is_a_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

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

	if( vips__get_bytes( filename, buf, 4 ) &&
		vips_foreign_load_gif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static void
vips_foreign_load_gif_parse( VipsForeignLoadGif *gif, 
	VipsImage *out )
{
	vips_image_init_fields( out, 
		gif->file->SWidth, gif->file->SHeight,
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );

	/* We have the whole GIF in memory, so we can render any area.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

	vips_image_set_int( out, "gif-n_pages", 
		gif->file->ImageCount );
}

static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	if( DGifSlurp( gif->file ) != GIF_OK ) { 
		vips_error( class->nickname, 
			_( "unable to decode GIF file: %s" ), 
			vips_foreign_load_gif_errstr( GifLastError() ) ); 
		return( -1 ); 
	}

	if( gif->page < 0 ||
		gif->page > gif->file->ImageCount ) {
		vips_error( class->nickname, 
			_( "unable to load page %d" ), gif->page );
		return( -1 ); 
	}

	vips_foreign_load_gif_parse( gif, load->out ); 

	return( 0 );
}

static void
vips_foreign_load_gif_render_line( VipsForeignLoadGif *gif,
	ColorMapObject *map, int width, int transparent,
	VipsPel * restrict q, VipsPel * restrict p )
{
	int x;

	for( x = 0; x < width; x++ ) {
		VipsPel v = p[x];

		if( v != transparent &&
			v < map->ColorCount ) {
			q[0] = map->Colors[v].Red;
			q[1] = map->Colors[v].Green;
			q[2] = map->Colors[v].Blue;
			q[3] = 255;
		}
		else {
			q[0] = 0;
			q[1] = 0;
			q[2] = 0;
			q[3] = 0;
		}

		q += 4;
	}
}

/* Render a SavedImage (a frame of a GIF) into an RGBA buffer. GIFs 
 * accumulate, so don't clear the buffer first, so that we can paint a 
 * series of frames on top of each other. 
 *
 * We can't easily render just a part of the buffer since SavedImages can be
 * interlaced, and they are annoying to paint in parts.
 */
static void
vips_foreign_load_gif_render_savedimage( VipsForeignLoadGif *gif,
	VipsImage *out, SavedImage *image ) {
	GifFileType *file = gif->file;

	/* Use the local colormap, if defined.
	 */
	ColorMapObject *map = image->ImageDesc.ColorMap ? 
		image->ImageDesc.ColorMap : file->SColorMap;

	VipsRect image_rect, gif_rect, clip;
	int gif_left, gif_top;
	int i, y;
	int transparent;

	/* Clip this savedimage position against the image size. Not all
	 * giflibs check this for us.
	 *
	 * If ImageDesc has been set maliciously we can still read outside 
	 * RasterBits, but at least we won't write outside out.
	 */
	image_rect.left = 0;
	image_rect.top = 0;
	image_rect.width = out->Xsize;
	image_rect.height = out->Ysize;
	gif_rect.left = image->ImageDesc.Left;
	gif_rect.top = image->ImageDesc.Top;
	gif_rect.width = image->ImageDesc.Width; 
	gif_rect.height = image->ImageDesc.Height; 
	vips_rect_intersectrect( &image_rect, &gif_rect, &clip ); 

	/* Therefore read at this offset in the SavedImage.
	 */
	gif_left = clip.left - image->ImageDesc.Left;
	gif_top = clip.top - image->ImageDesc.Top;

	/* Does this SavedImage have transparency?
	 */
	transparent = -1;
	for( i = 0; i < image->ExtensionBlockCount; i++ ) {
		ExtensionBlock *block = &image->ExtensionBlocks[i];

		if( block->Function != GRAPHICS_EXT_FUNC_CODE ) 
			continue;

		 if( block->Bytes[0] & 0x01 ) 
			transparent = block->Bytes[GIF_GCE_TRANSPARENCY_BYTE];
	}

	if( image->ImageDesc.Interlace ) {
		int i;
		int input_y;

		input_y = gif_top;
		for( i = 0; i < 4; i++ ) {
			for( y = InterlacedOffset[i]; 
				y < clip.height;
			  	y += InterlacedJumps[i] ) {
				vips_foreign_load_gif_render_line( gif, map, 
					clip.width, transparent,
					VIPS_IMAGE_ADDR( out, 
						clip.left, clip.top + y ),
					image->RasterBits +
				       		gif_left + 
						input_y * 
						   image->ImageDesc.Width );
				input_y += 1;
			}
		}
	}
	else {
		for( y = 0; y < clip.height; y++ ) {
			vips_foreign_load_gif_render_line( gif, map, 
				clip.width, transparent,
				VIPS_IMAGE_ADDR( out, clip.left, clip.top + y ),
				image->RasterBits + 
					gif_left + 
					(gif_top + y) * 
					   image->ImageDesc.Width );
		}
	}
}

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	int i;

	vips_foreign_load_gif_parse( gif, load->real ); 

	/* Turn out into a memory image which we then render the GIF frames
	 * into.
	 */
	if( vips_image_write_prepare( load->real ) )
		return( -1 );

	for( i = 0; i <= gif->page; i++ ) 
		vips_foreign_load_gif_render_savedimage( gif, 
			load->real, &gif->file->SavedImages[i] ); 

	/* We've rendered to a memory image ... we can free the GIF image 
	 * struct now.
	 */
	VIPS_FREEF( DGifCloseFile, gif->file );

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

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;
	load_class->load = vips_foreign_load_gif_load;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, page ),
		0, 100000, 0 );

}

static void
vips_foreign_load_gif_init( VipsForeignLoadGif *gif )
{
}

typedef struct _VipsForeignLoadGifFile {
	VipsForeignLoadGif parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadGifFile;

typedef VipsForeignLoadGifClass VipsForeignLoadGifFileClass;

G_DEFINE_TYPE( VipsForeignLoadGifFile, vips_foreign_load_gif_file, 
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_file_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) load;

	if( !(gif->file = DGifOpenFileName( file->filename )) ) { 
		vips_error( class->nickname, 
			"%s", _( "unable to open GIF file" ) ); 
		return( -1 ); 
	}

	return( vips_foreign_load_gif_header( load ) );
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

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

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

/* Callback from the gif loader.
 *
 * Read up to len bytes into buffer, return number of bytes read, 0 for EOF.
 */
static int
vips_foreign_load_gif_buffer_read( GifFileType *file, 
	GifByteType *buf, int len )
{
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *)
		file->UserData;
	size_t will_read = VIPS_MIN( len, buffer->bytes_to_go );

	memcpy( buf, buffer->p, will_read );
	buffer->p += will_read;
	buffer->bytes_to_go -= will_read;

	return( will_read ); 
}

static int
vips_foreign_load_gif_buffer_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifBuffer *buffer = 
		(VipsForeignLoadGifBuffer *) load;

	/* Init the read point.
	 */
	buffer->p = buffer->buf->data;
	buffer->bytes_to_go = buffer->buf->length;

	if( !(gif->file = DGifOpen( gif, 
		vips_foreign_load_gif_buffer_read )) ) { 
		vips_error( class->nickname, 
			"%s", _( "unable to open GIF file" ) ); 
		return( -1 ); 
	}

	return( vips_foreign_load_gif_header( load ) );
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
	object_class->description = _( "load GIF with giflib" );

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

#endif /*HAVE_RSVG*/

