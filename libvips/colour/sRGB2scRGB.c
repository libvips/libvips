/* Turn displayable rgb files to scRGB.
 *
 * Modified:
 * 15/11/94 JC
 *	- memory leak fixed
 *	- error message added
 * 16/11/94 JC
 *	- partialed
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
 * 6/11/12
 * 	- add 16-bit sRGB import
 * 11/12/12
 * 	- cut about to make sRGB2scRGB.c
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
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourCode VipssRGB2scRGB;
typedef VipsColourCodeClass VipssRGB2scRGBClass;

G_DEFINE_TYPE( VipssRGB2scRGB, vips_sRGB2scRGB, VIPS_TYPE_COLOUR_CODE );

/* Convert a buffer of 8-bit pixels.
 */
static void
vips_sRGB2scRGB_line_8( float * restrict q, VipsPel * restrict p, int width )
{
	int i;

	for( i = 0; i < width; i++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];

		float R, G, B;

		p += 3;

		vips_col_sRGB2scRGB_8( r, g, b, &R, &G, &B );

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;
	}
}

/* Convert a buffer of 16-bit pixels.
 */
static void
vips_sRGB2scRGB_line_16( float * restrict q, unsigned short * restrict p, 
	int width )
{
	int i;

	for( i = 0; i < width; i++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];

		float R, G, B;

		p += 3;

		vips_col_sRGB2scRGB_16( r, g, b, &R, &G, &B );

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;
	}
}

static void
vips_sRGB2scRGB_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	if( colour->in[0]->BandFmt == VIPS_FORMAT_UCHAR )
		vips_sRGB2scRGB_line_8( (float *) out, 
			(VipsPel *) in[0], width );
	else
		vips_sRGB2scRGB_line_16( (float *) out, 
			(unsigned short *) in[0], width );
}

static int
vips_sRGB2scRGB_build( VipsObject *object )
{
	VipsColourCode *code = (VipsColourCode *) object;

	if( code->in ) 
		code->input_format = 
			code->in->BandFmt == VIPS_FORMAT_USHORT ? 
			VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;

	if( VIPS_OBJECT_CLASS( vips_sRGB2scRGB_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_sRGB2scRGB_class_init( VipssRGB2scRGBClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "sRGB2scRGB";
	object_class->description = _( "convert an sRGB image to scRGB" );
	object_class->build = vips_sRGB2scRGB_build;

	colour_class->process_line = vips_sRGB2scRGB_line;
}

static void
vips_sRGB2scRGB_init( VipssRGB2scRGB *sRGB2scRGB )
{
	VipsColour *colour = VIPS_COLOUR( sRGB2scRGB );
	VipsColourCode *code = VIPS_COLOUR_CODE( sRGB2scRGB );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_scRGB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->input_bands = 3;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_NONE;

	/* The default. This can get changed above ^^ if we see a 
	 * 16-bit input.
	 */
	code->input_format = VIPS_FORMAT_UCHAR;
}

/**
 * vips_sRGB2scRGB:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert an sRGB image to scRGB.
 *
 * See also: vips_sRGB2XYZ(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sRGB2scRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sRGB2scRGB", ap, in, out );
	va_end( ap );

	return( result );
}
