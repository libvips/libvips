/* vips_text
 *
 * Written on: 20/5/04
 * 29/7/04
 *	- !HAVE_PANGOFT2 was broken, thanks Kenneth
 * 15/11/04
 *	- gah, still broken, thanks Stefan
 * 5/4/06
 * 	- return an error for im_text( "" ) rather than trying to make an
 * 	  empty image
 * 2/2/10
 * 	- gtkdoc
 * 3/6/13
 * 	- rewrite as a class
 * 20/9/15 leiyangyou 
 * 	- add @spacing 
 * 29/5/17
 * 	- don't set "font" if unset, it breaks caching
 * 16/7/17
 * 	- implement auto fitting of text inside bounds
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <vips/vips.h>

#ifdef HAVE_PANGOFT2

#include <pango/pango.h>
#include <pango/pangoft2.h>

#include "pcreate.h"

typedef struct _VipsText {
	VipsCreate parent_instance;

	char *text;
	char *font;
	int width;
	int height;
	int spacing;
	VipsAlign align;
	int dpi;
	VipsGravity gravity;

	FT_Bitmap bitmap;
	PangoContext *context;
	PangoLayout *layout;

} VipsText;

typedef VipsCreateClass VipsTextClass;

typedef struct _FontSizeList FontSizeList;

struct _FontSizeList {
	int deviation;
	int size;
	long area;
	FontSizeList *next;
};

G_DEFINE_TYPE( VipsText, vips_text, VIPS_TYPE_CREATE );

/* Just have one of these and reuse it.
 *
 * This does not unref cleanly on many platforms, so we will leak horribly
 * unless we reuse it. Sadly this means vips_text() needs to use a lock 
 * internally to single-thread text rendering.
 */
static PangoFontMap *vips_text_fontmap = NULL;

/* ... single-thread the body of vips_text() with this.
 */
static GMutex *vips_text_lock = NULL; 

static void
vips_text_dispose( GObject *gobject )
{
	VipsText *text = (VipsText *) gobject;

	VIPS_UNREF( text->layout ); 
	VIPS_UNREF( text->context ); 
	VIPS_FREE( text->bitmap.buffer ); 

	G_OBJECT_CLASS( vips_text_parent_class )->dispose( gobject );
}

static PangoLayout *
text_layout_new( PangoContext *context, 
	const char *text, const char *font, int width, int spacing,
	VipsAlign align )
{
	PangoLayout *layout;
	PangoFontDescription *font_description;
	PangoAlignment palign;

	layout = pango_layout_new( context );
	pango_layout_set_markup( layout, text, -1 );

	font_description = pango_font_description_from_string( font );
	pango_layout_set_font_description( layout, font_description );
	pango_font_description_free( font_description );

	if( width > 0 )
		pango_layout_set_width( layout, width * PANGO_SCALE );

	if( spacing > 0 )
		pango_layout_set_spacing( layout, spacing * PANGO_SCALE );

	switch( align ) {
	case VIPS_ALIGN_LOW:
		palign = PANGO_ALIGN_LEFT;
		break;

	case VIPS_ALIGN_CENTRE:
		palign = PANGO_ALIGN_CENTER;
		break;

	case VIPS_ALIGN_HIGH:
		palign = PANGO_ALIGN_RIGHT;
		break;

	default:
		palign = PANGO_ALIGN_LEFT;
		break;
	}
	pango_layout_set_alignment( layout, palign );

	return( layout );
}

static int
digits_in_num( int f )
{
	int digits = 0;
	if( f == 0 )
		return 1;
	while( f ) {
		f /= 10;
		digits++;
	}
	return digits;
}

static int
determine_deviation( int width, int height, PangoRectangle rect ) {
	int rect_width = PANGO_PIXELS( rect.width );
	int rect_height = PANGO_PIXELS( rect.height );

	int dw = (int)( 100 * (double)abs( rect_width - width ) / width );
	int dh = (int)( 100 * (double)abs( rect_height - height ) / height );

	if( dw && dh ) {
		return dw * dh;
	}
	return dw ? dw : dh;
}

static bool
search_flist( FontSizeList *flist, int size )
{
	FontSizeList *entry = flist;
	while( entry->next != NULL ) {
		if( entry->size == size )
			return true;
		entry = entry->next;
	}
	return false;
}

static FontSizeList *
least_deviation_flist( FontSizeList *flist )
{
	FontSizeList *entry = flist;
	// This works for all practical purposes
	long smallest = 1999999999;
	FontSizeList *least;
	while( entry->next != NULL ) {
		if( entry->deviation < smallest ) {
			smallest = entry->deviation;
			least = entry;
		}
		entry = entry->next;
	}
	return least;
}

static void
append_to_flist( FontSizeList *flist, FontSizeList *nflist )
{
	FontSizeList *entry = flist;
	while( entry->next != NULL ) {
		entry = entry->next;
	}
	entry->next = nflist;
}

static PangoRectangle
fit_to_bounds( VipsText *text,
	int tolerance, char *name, int size, PangoRectangle rect,
	FontSizeList *flist, bool coarse )
{
	int buf_size = strlen( name ) + digits_in_num( size ) + 2;
	int deviation;
	char buf[ buf_size ];
	long font_area = (long)PANGO_PIXELS( rect.width ) *
		(long)PANGO_PIXELS( rect.height );
	long allowed_area = (long)text->width * (long)text->height;

	FontSizeList *nflist = (FontSizeList *) malloc( sizeof( FontSizeList ) );

	if( coarse ) {
		// A factor of X increase in font size causes X^2 increase in the area
		// occupied by the text
		size = (int)((double)size * sqrt( (double)allowed_area / font_area ));
	} else {
		if( allowed_area > font_area ) {
			size++;
		} else {
			size--;
		}
	}

	snprintf( buf, buf_size, "%s %d", name, size );

	text->layout = text_layout_new( text->context,
		text->text, buf, text->width, text->spacing, text->align );

	pango_layout_get_extents( text->layout, &rect, NULL );

	deviation = determine_deviation( text->width, text->height, rect );

	nflist->size = size;
	nflist->deviation = deviation;
	nflist->area = PANGO_PIXELS( rect.width ) * PANGO_PIXELS( rect.height );
	nflist->next = NULL;
	append_to_flist( flist, nflist );

	// If we have been through this font size before, find the one with the
	// smallest deviation and then fit in small adjustments
	if( search_flist( flist, size ) ) {
		if( coarse ) {
			return fit_to_bounds( text, tolerance, name, size, rect,
				least_deviation_flist( flist ), false );
		} else {
			// We cannot do better than this because we will
			// cycle through sizes again
			return rect;
		}
	}

	if( deviation > tolerance )  {
		return fit_to_bounds( text, tolerance, name, size, rect, flist, coarse );
	} else {
		return rect;
	}
}

static int
vips_text_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsText *text = (VipsText *) object;
	FontSizeList *flist = (FontSizeList *) malloc( sizeof( FontSizeList ) );

	PangoRectangle logical_rect;
	PangoRectangle ink_rect;
	int left;
	int top;
	int width;
	int height;
	int y;
	int deviation = 0;
	int font_size = 0;
	char *last;
	bool is_font_size_provided = true;

	// TODO: Should user be allowed to change this?
	const int TOLERANCE = 100; // 10% * 10% for width, height

	if( VIPS_OBJECT_CLASS( vips_text_parent_class )->build( object ) )
		return( -1 );

	if( !pango_parse_markup( text->text, -1, 0, NULL, NULL, NULL, NULL ) ) {
		vips_error( class->nickname, 
			"%s", _( "invalid markup in text" ) );
		return( -1 );
	}

	char *font_name[ strlen( text->font ) + 1 ];
	// Extract font size from provided argument
	last = strrchr( text->font, ' ' );

	// Happens for a single word font names
	if( last != '\0' ) {
		font_size = atol( last );
	}

	if( font_size ) {
		strncat( font_name, text->font, last - text->font );
	} else {
		// Font was more than 1 word. "Fira Code" would have last
		// pointing to "Code", leading atol to output 0
		// Fix font_name back to the original in this case
		strcpy( font_name, text->font );
		font_size = text->height;
		is_font_size_provided = false;
	}

	g_mutex_lock( vips_text_lock ); 

	if( !vips_text_fontmap )
		vips_text_fontmap = pango_ft2_font_map_new();

	pango_ft2_font_map_set_resolution( 
		PANGO_FT2_FONT_MAP( vips_text_fontmap ), text->dpi, text->dpi );
	text->context = pango_font_map_create_context( 
		PANGO_FONT_MAP( vips_text_fontmap ) );

	if( !(text->layout = text_layout_new( text->context, 
		text->text, text->font, 
		text->width, text->spacing, text->align )) ) {
		g_mutex_unlock( vips_text_lock ); 
		return( -1 );
	}

	pango_layout_get_extents( text->layout, &ink_rect, &logical_rect );

	if( !is_font_size_provided ) {
		if( text->height && text->width ) {
			deviation = determine_deviation( text->width, text->height, ink_rect );
		}

		if( deviation > TOLERANCE ) {
			flist->size = font_size;
			flist->deviation = deviation;
			flist->area = PANGO_PIXELS( ink_rect.width ) * PANGO_PIXELS( ink_rect.height );
			flist->next = NULL;

			logical_rect = fit_to_bounds( text, TOLERANCE, font_name,
				font_size, ink_rect, flist, true );
		}

		// Logical rect does not help us with exact bounds of the text
		pango_layout_get_extents( text->layout, &ink_rect, NULL );
	}


#ifdef DEBUG
	printf( "logical left = %d, top = %d, width = %d, height = %d\n",
		PANGO_PIXELS( logical_rect.x ),
		PANGO_PIXELS( logical_rect.y ),
		PANGO_PIXELS( logical_rect.width ),
		PANGO_PIXELS( logical_rect.height ) );
	printf( "ink left = %d, top = %d, width = %d, height = %d\n",
		PANGO_PIXELS( ink_rect.x ),
		PANGO_PIXELS( ink_rect.y ),
		PANGO_PIXELS( ink_rect.width ),
		PANGO_PIXELS( ink_rect.height ) );
#endif /*DEBUG*/

	left = PANGO_PIXELS( logical_rect.x );
	top = PANGO_PIXELS( logical_rect.y );
	width = PANGO_PIXELS( logical_rect.width );
	height = PANGO_PIXELS( logical_rect.height );

	// Match the layout to fit the exact dimensions requested
	// We also apply gravity here
	if( !is_font_size_provided && text->width && text->height ) {
		left = 0;
		top = 0;
		width = PANGO_PIXELS( ink_rect.width );
		height = PANGO_PIXELS( ink_rect.height );
		
		// Since the layout is bigger than the requested dimensions, we
		// scale the layout font description by the same scale
		// This seems like the only way to resize the layout before it
		// is rendered. We cannot reliably do resizing after rendering
		// because we lose the lock, and we need to rely on vips_resize
		if( width > text->width || height > text->height ) {
			double scale_w = (double)text->width / width;
			double scale_h = (double)text->height / height;
			double scale = scale_w > scale_h ? scale_h : scale_w;
			PangoFontDescription *temp_fd = pango_font_description_copy( 
				pango_layout_get_font_description( text->layout ) );
			int fz = pango_font_description_get_size( temp_fd );
			pango_font_description_set_size( temp_fd, (int)(fz * scale) );
			pango_layout_set_font_description( text->layout, temp_fd );
			pango_font_description_free( temp_fd );

			pango_layout_get_extents( text->layout, &ink_rect, NULL );

			width = PANGO_PIXELS( ink_rect.width );
			height = PANGO_PIXELS( ink_rect.height );
		}

		switch( text->gravity ) {
			case VIPS_GRAVITY_CENTER:
				left = ( text->width - width ) / 2;
				top = ( text->height - height ) / 2;
				break;
			case VIPS_GRAVITY_NORTH:
				left = ( text->width - width ) / 2;
				break;
			case VIPS_GRAVITY_EAST:
				left = text->width - width;
				top = ( text->height - height ) / 2;
				break;
			case VIPS_GRAVITY_SOUTH:
				left = ( text->width - width ) / 2;
				top = text->height - height;
				break;
			case VIPS_GRAVITY_WEST:
				top = ( text->height - height ) / 2;
				break;
			case VIPS_GRAVITY_NORTH_EAST:
				left = text->width - width;
				break;
			case VIPS_GRAVITY_SOUTH_EAST:
				left = text->width - width;
				top = text->height - height;
				break;
			case VIPS_GRAVITY_SOUTH_WEST:
				top = text->height - height;
				break;
			case VIPS_GRAVITY_NORTH_WEST:
				break;
			default:
				left = ( text->width - width ) / 2;
				top = ( text->height - height ) / 2;
				break;
		}
		left = -1 * left;
		top = -1 * top;
		width = text->width;
		height = text->height;
	}

	/* Can happen for "", for example.
	 */
	if( width == 0 || height == 0 ) {
		vips_error( class->nickname, "%s", _( "no text to render" ) );
		g_mutex_unlock( vips_text_lock ); 
		return( -1 );
	}

	text->bitmap.width = width;
	text->bitmap.pitch = (text->bitmap.width + 3) & ~3;
	text->bitmap.rows = height;
	if( !(text->bitmap.buffer = 
		VIPS_ARRAY( NULL, 
			text->bitmap.pitch * text->bitmap.rows, VipsPel )) ) {
		g_mutex_unlock( vips_text_lock ); 
		return( -1 );
	}
	text->bitmap.num_grays = 256;
	text->bitmap.pixel_mode = ft_pixel_mode_grays;
	memset( text->bitmap.buffer, 0x00, 
		text->bitmap.pitch * text->bitmap.rows );

	if( pango_layout_get_width( text->layout ) != -1 )
		pango_ft2_render_layout( &text->bitmap, text->layout, 
			-left, -top );
	else
		pango_ft2_render_layout( &text->bitmap, text->layout, 0, 0 );

	g_mutex_unlock( vips_text_lock ); 

	vips_image_init_fields( create->out,
		text->bitmap.width, text->bitmap.rows, 1, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 ); 
	vips_image_pipelinev( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	for( y = 0; y < text->bitmap.rows; y++ ) 
		if( vips_image_write_line( create->out, y, 
			(VipsPel *) text->bitmap.buffer + 
				y * text->bitmap.pitch ) )
			return( -1 );

	return( 0 );
}

static void *
vips_text_make_lock( void *client )
{
	if( !vips_text_lock ) 
		vips_text_lock = vips_g_mutex_new();

	return( NULL );
}

static void
vips_text_class_init( VipsTextClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, vips_text_make_lock, NULL );

	gobject_class->dispose = vips_text_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "text";
	vobject_class->description = _( "make a text image" );
	vobject_class->build = vips_text_build;

	VIPS_ARG_STRING( class, "text", 4, 
		_( "Text" ), 
		_( "Text to render" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsText, text ),
		NULL ); 

	VIPS_ARG_STRING( class, "font", 5, 
		_( "Font" ), 
		_( "Font to render with" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, font ),
		NULL ); 

	VIPS_ARG_INT( class, "width", 6, 
		_( "Width" ), 
		_( "Maximum image width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, width ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "height", 7, 
		_( "Height" ), 
		_( "Maximum image height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, height ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_ENUM( class, "align", 8, 
		_( "Align" ), 
		_( "Align on the low, centre or high edge" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, align ),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW );

	VIPS_ARG_INT( class, "dpi", 9, 
		_( "DPI" ), 
		_( "DPI to render at" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, dpi ),
		1, 1000000, 72 );

	VIPS_ARG_INT( class, "spacing", 10, 
		_( "Spacing" ), 
		_( "Line spacing" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, spacing ),
		0, 1000000, 0 );

	VIPS_ARG_ENUM( class, "gravity", 11, 
		_( "Gravity" ), 
		_( "Gravity to use while auto fitting text in bounds" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, gravity ),
		VIPS_TYPE_GRAVITY, VIPS_GRAVITY_CENTER );

}

static void
vips_text_init( VipsText *text )
{
	text->align = VIPS_ALIGN_LOW;
	text->dpi = 72;
	text->bitmap.buffer = NULL;
	VIPS_SETSTR( text->font, "sans 12" ); 
}

#endif /*HAVE_PANGOFT2*/

/**
 * vips_text:
 * @out: output image
 * @text: utf-8 text string to render
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @font: %gchararray, font to render with
 * * @width: %gint, image should be no wider than this many pixels
 * * @height: %gint, image should be no higher than this many pixels
 * * @align: #VipsAlign, left/centre/right alignment
 * * @dpi: %gint, render at this resolution
 * * @spacing: %gint, space lines by this in points
 * * @gravity: #VipsGravity, gravity of text
 *
 * Draw the string @text to an image. @out is a one-band 8-bit
 * unsigned char image, with 0 for no text and 255 for text. Values inbetween
 * are used for anti-aliasing.
 *
 * @text is the text to render as a UTF-8 string. It can contain Pango markup,
 * for example "&lt;i&gt;The&lt;/i&gt;Guardian".
 *
 * @font is the font to render with, as a fontconfig name. Examples might be
 * "sans 12" or perhaps "bitstream charter bold 10".
 *
 * @width is the maximum number of pixels across to draw within. If the
 * generated text is wider than this, it will wrap to a new line. In this
 * case, @align can be used to set the alignment style for multi-line
 * text. 
 *
 * @height is the maximum number of pixels high the generated text can be. This
 * only takes effect when there is no font size specified, and a width is
 * provided, making a box. If a font size is provided, we render the font size
 * without any fitting to box. Bounds might be exceeded if the font size is too
 * big to be fit or wrapped inside.
 *
 * @dpi sets the resolution to render at. "sans 12" at 72 dpi draws characters
 * approximately 12 pixels high.
 *
 * @spacing sets the line spacing, in points. It would typicallly be something
 * like font size times 1.2.
 *
 * @gravity determines the position of the text inside the bounds. This is only
 * applied opportunistically if the bounds are bigger than the text
 *
 * See also: vips_xyz(), vips_text(), vips_gaussnoise().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_text( VipsImage **out, const char *text, ... )
{
	va_list ap;
	int result;

	va_start( ap, text );
	result = vips_call_split( "text", ap, out, text );
	va_end( ap );

	return( result );
}
