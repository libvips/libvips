/* Shared code for cairo based loaders like svgload and pdfload.
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

#if defined(HAVE_RSVG) || defined(HAVE_POPPLER)

#include <vips/vips.h>
#include <vips/internal.h>

/* Convert from ARGB to RGBA and undo premultiplication. 
 */
void
vips__cairo2rgba( guint32 * restrict buf, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		guint32 * restrict p = buf + i;
		guint32 x = *p;
		guint8 a = x >> 24;
		VipsPel * restrict out = (VipsPel *) p;

		if( a == 255 ) 
			*p = GUINT32_TO_BE( (x << 8) | 255 );
		else if( a == 0 ) 
			*p = GUINT32_TO_BE( x << 8 );
		else {
			/* Undo premultiplication.
			 */
			out[0] = 255 * ((x >> 16) & 255) / a;
			out[1] = 255 * ((x >> 8) & 255) / a;
			out[2] = 255 * (x & 255) / a;
			out[3] = a;
		}
	}
}

#endif
