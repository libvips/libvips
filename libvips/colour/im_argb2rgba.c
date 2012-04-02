/* Convert pre-multipled argb to rgba
 *
 * 11/12/11
 * 	- from im_rad2float.c
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
#include <math.h>

#include <vips/vips.h>

static void
argb2rgba( guint32 *in, VipsPel *out, int n, void *_bg )
{
	guint32 bg = GPOINTER_TO_UINT( _bg );

	int i;

	for( i = 0; i < n; i++ ) {
		guint32 x = in[i];
		guint8 a = x >> 24;

		/* Convert from ARGB to RGBA and undo premultiplication.
		 */
		if( a != 0 ) {
			out[0] = 255 * ((x >> 16) & 255) / a;
			out[1] = 255 * ((x >> 8) & 255) / a;
			out[2] = 255 * (x & 255) / a;
		} 
		else {
			/* Use background color.
			 */
			out[0] = (bg >> 16) & 255;
			out[1] = (bg >> 8) & 255;
			out[2] = bg & 255;
		}
		out[3] = a;

		out += 4;
	}
}

/**
 * im_argb2rgba:
 * @in: input image
 * @out: output image
 *
 * Convert Cairo-style pre-multiplied argb to png-style rgba. Background
 * pixels are painted with the metadata item "background-rgb".
 *
 * See also: im_openslide2vips().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_argb2rgba( VipsImage *in, IMAGE *out )
{
	guint32 bg;

	if( vips_check_coding_argb( "argb2rgba", in ) ||
		im_cp_desc( out, in ) )
		return( -1 );
	out->Coding = IM_CODING_NONE;

	if( vips_image_get_int( in, VIPS_META_BACKGROUND_RGB, (int *) &bg ) )
		bg = 0xffffff;

	if( im_wrapone( in, out, 
		(im_wrapone_fn) argb2rgba, GUINT_TO_POINTER( bg ), NULL ) )
		return( -1 );

	return( 0 );
}
