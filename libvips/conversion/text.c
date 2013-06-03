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

#ifdef HAVE_PANGOFT2

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>

#include <pango/pango.h>
#include <pango/pangoft2.h>

#include "conversion.h"

typedef struct _VipsText {
	VipsConversion parent_instance;

	char *text;
	char *font;
	int width;
	VipsAlign align;
	int dpi;

	FT_Bitmap bitmap;
	PangoContext *context;
	PangoLayout *layout;

} VipsText;

typedef VipsConversionClass VipsTextClass;

G_DEFINE_TYPE( VipsText, vips_text, VIPS_TYPE_CONVERSION );

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
	const char *text, const char *font, int width, 
	VipsAlign align, int dpi )
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
vips_text_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsText *text = (VipsText *) object;

	PangoRectangle logical_rect;
	int left;
	int top;
	int width;
	int height;
	int y;

	if( VIPS_OBJECT_CLASS( vips_text_parent_class )->build( object ) )
		return( -1 );

	if( !pango_parse_markup( text->text, -1, 0, NULL, NULL, NULL, NULL ) ) {
		vips_error( class->nickname, 
			"%s", _( "invalid markup in text" ) );
		return( -1 );
	}

	if( !text->font )
		g_object_set( text, "font", "sans 12", NULL ); 

	g_mutex_lock( vips_text_lock ); 

	if( !vips_text_fontmap )
		vips_text_fontmap = pango_ft2_font_map_new();

	pango_ft2_font_map_set_resolution( 
		PANGO_FT2_FONT_MAP( vips_text_fontmap ), text->dpi, text->dpi );
	text->context = pango_font_map_create_context( 
		PANGO_FONT_MAP( vips_text_fontmap ) );

	if( !(text->layout = text_layout_new( text->context, 
		text->text, text->font, text->width, text->align, text->dpi )) )
		return( -1 );

	pango_layout_get_extents( text->layout, NULL, &logical_rect );

#ifdef DEBUG
	printf( "logical left = %d, top = %d, width = %d, height = %d\n",
		PANGO_PIXELS( logical_rect.x ),
		PANGO_PIXELS( logical_rect.y ),
		PANGO_PIXELS( logical_rect.width ),
		PANGO_PIXELS( logical_rect.height ) );
#endif /*DEBUG*/

	left = PANGO_PIXELS( logical_rect.x );
	top = PANGO_PIXELS( logical_rect.y );
	width = PANGO_PIXELS( logical_rect.width );
	height = PANGO_PIXELS( logical_rect.height );

	/* Can happen for "", for example.
	 */
	if( width == 0 || height == 0 ) {
		vips_error( class->nickname, "%s", _( "no text to render" ) );
		return( -1 );
	}

	text->bitmap.width = width;
	text->bitmap.pitch = (text->bitmap.width + 3) & ~3;
	text->bitmap.rows = height;
	if( !(text->bitmap.buffer = 
		im_malloc( NULL, text->bitmap.pitch * text->bitmap.rows )) )
		return( -1 );
	text->bitmap.num_grays = 256;
	text->bitmap.pixel_mode = ft_pixel_mode_grays;
	memset( text->bitmap.buffer, 0x00, 
		text->bitmap.pitch * text->bitmap.rows );

	if( pango_layout_get_width( text->layout ) != -1 )
		pango_ft2_render_layout( &text->bitmap, text->layout, 
			-left, -top );
	else
		pango_ft2_render_layout( &text->bitmap, text->layout, 0, 0 );

	vips_image_init_fields( conversion->out,
		text->bitmap.width, text->bitmap.rows, 1, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 ); 
	vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	for( y = 0; y < text->bitmap.rows; y++ ) 
		if( vips_image_write_line( conversion->out, y, 
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

	VIPS_ARG_STRING( class, "font", 4, 
		_( "Font" ), 
		_( "Font to render width" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, font ),
		NULL ); 

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Maximum image width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, width ),
		0, 1000000, 0 );

	VIPS_ARG_ENUM( class, "align", 5, 
		_( "Align" ), 
		_( "Align on the low, centre or high coordinate edge" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, align ),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW ); 

	VIPS_ARG_INT( class, "dpi", 4, 
		_( "DPI" ), 
		_( "DPI to render at" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsText, dpi ),
		1, 1000000, 72 );

}

static void
vips_text_init( VipsText *text )
{
	text->align = VIPS_ALIGN_LOW;
	text->dpi = 72;
	text->bitmap.buffer = NULL;
}

/**
 * vips_text:
 * @out: output image
 * @text: utf-8 text string to render
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @font: font to render with
 * @width: render within this many pixels across
 * @alignment: left/centre/right alignment
 * @dpi: render at this resolution
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
 * case, @alignment can be used to set the alignment style for multi-line
 * text. 0 means left-align, 1 centre, 2 right-align.
 *
 * @dpi sets the resolution to render at. "sans 12" at 72 dpi draws characters
 * approximately 12 pixels high.
 *
 * See also: vips_make_xy(), vips_text(), vips_gaussnoise().
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

#endif /*HAVE_PANGOFT2*/
