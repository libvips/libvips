/* @(#) Make an image containting text as a bitmap. One band uchar output,
 * @(#) with 0 - 255 for black - white.
 * @(#)
 * @(#) int 
 * @(#) im_text( IMAGE *out, const char *text, const char *font, 
 * @(#) 	int width, int alignment, int dpi ) 
 * @(#)
 * @(#) Font is a Pango font specification, eg. "Sans 12", or "Times News
 * @(#) Roman Italic 12". text should be coded as utf-8. dpi is resolution
 * @(#) in dots per inch. alignment is 0, 1 and 2 for right, centre and left 
 * @(#) alignment. width is the wrap width in pixels.
 * @(#)
 * @(#) Returns 0 on success and -1 on error.
 *
 * Written on: 20/5/04
 * 29/7/04
 *	- !HAVE_PANGOFT2 was broken, thanks Kenneth
 * 15/11/04
 *	- gah, still broken, thanks Stefan
 * 5/4/06
 * 	- return an error for im_text( "" ) rather than trying to make an
 * 	  empty image
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include <vips/vips.h>

#ifdef HAVE_PANGOFT2
#include <pango/pango.h>
#include <pango/pangoft2.h>
#endif /*HAVE_PANGOFT2*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#ifdef HAVE_PANGOFT2

static PangoLayout *
text_layout_new( PangoContext *context, 
	const char *text, const char *font, int width, int alignment, int dpi )
{
	PangoLayout *layout;
	PangoFontDescription *font_description;

	layout = pango_layout_new( context );
	pango_layout_set_markup( layout, text, -1 );

	font_description = pango_font_description_from_string( font );
	pango_layout_set_font_description( layout, font_description );
	pango_font_description_free( font_description );

	if( width > 0 )
		pango_layout_set_width( layout, width * PANGO_SCALE );

	if( alignment < 0 || alignment > 2 )
		alignment = PANGO_ALIGN_RIGHT;
	pango_layout_set_alignment( layout, (PangoAlignment) alignment );

	return( layout );
}

static int
text_ft_to_vips( FT_Bitmap *bitmap, IMAGE *out )
{
	int y;
	
	if( im_outcheck( out ) )
                return( -1 );
        im_initdesc( out, bitmap->width, bitmap->rows, 1, 
		IM_BBITS_BYTE, IM_BANDFMT_UCHAR,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( out ) )
                return( -1 );

	for( y = 0; y < bitmap->rows; y++ ) 
		if( im_writeline( y, out, 
			(PEL *) bitmap->buffer + y * bitmap->pitch ) )
			return( -1 );

	return( 0 );
}

static int
text_layout_render_to_image( PangoLayout *layout, IMAGE *out )
{
	PangoRectangle logical_rect;
	FT_Bitmap bitmap;
	int left;
	int top;
	int width;
	int height;

	pango_layout_get_extents( layout, NULL, &logical_rect );

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
		im_error( "im_text", _( "no text to render" ) );
		return( -1 );
	}

	bitmap.width = width;
	bitmap.pitch = (bitmap.width + 3) & ~3;
	bitmap.rows = height;
	if( !(bitmap.buffer = im_malloc( NULL, bitmap.pitch * bitmap.rows )) )
		return( -1 );
	bitmap.num_grays = 256;
	bitmap.pixel_mode = ft_pixel_mode_grays;
	memset( bitmap.buffer, 0x00, bitmap.pitch * bitmap.rows );

	if( pango_layout_get_width( layout ) != -1 )
		pango_ft2_render_layout( &bitmap, layout, -left, -top );
	else
		pango_ft2_render_layout( &bitmap, layout, 0, 0 );
	if( text_ft_to_vips( &bitmap, out ) ) {
		im_free( bitmap.buffer );
		return( -1 );
	}

	im_free( bitmap.buffer );

	return( 0 );
}

static int
text_render_to_image( PangoContext *context, IMAGE *out, 
	const char *text, const char *font, int width, int alignment, int dpi )
{
	PangoLayout *layout;

	if( !(layout = text_layout_new( context, text, font, 
		width, alignment, dpi )) )
		return( -1 );

	if( text_layout_render_to_image( layout, out ) ) {
		g_object_unref( layout );
		return( -1 );
	}

	g_object_unref( layout );

	return( 0 );
}

int 
im_text( IMAGE *out, const char *text, const char *font, 
	int width, int alignment, int dpi )
{
	static PangoFontMap *fontmap = NULL;
	PangoContext *context;

	if( !pango_parse_markup( text, -1, 0, NULL, NULL, NULL, NULL ) ) {
		im_error( "im_text", _( "invalid markup in text" ) );
		return( -1 );
	}

	/* Just have one of these, ever. It doesn't close properly when we
	 * _unref(), so keep it around for reuse.
	 */
	if( !fontmap )
		fontmap = pango_ft2_font_map_new();

	pango_ft2_font_map_set_resolution( PANGO_FT2_FONT_MAP( fontmap ), 
		dpi, dpi );
	context = pango_ft2_font_map_create_context( 
		PANGO_FT2_FONT_MAP( fontmap ) );

	if( text_render_to_image( context, out, text, font, 
		width, alignment, dpi ) ) {
		g_object_unref( context );
		return( -1 );
	}

	g_object_unref( context );

	return( 0 );
}

#else /*!HAVE_PANGOFT2*/

int 
im_text( IMAGE *out, const char *text, const char *font, 
	int width, int alignment, int dpi )
{
	im_error( "im_text", _( "pangoft2 support disabled" ) );

	return( -1 );
}

#endif /*HAVE_PANGOFT2*/
