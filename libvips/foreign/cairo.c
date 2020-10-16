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

#include <vips/vips.h>
#include <vips/internal.h>

/* Convert from Cairo's BGRA to RGBA and undo premultiplication. 
 *
 * See also openslide's argb2rgba().
 */
void
vips__cairo2rgba( guint32 * restrict buf, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		guint32 bgra = GUINT32_FROM_BE( buf[i] );
		guint8 a = bgra & 0xff;

                guint32 rgba;

                if( a == 0 || 
                        a == 255 )
			rgba = 
				(bgra & 0x00ff00ff) |
			        (bgra & 0x0000ff00) << 16 |
			        (bgra & 0xff000000) >> 16;
                else
                        /* Undo premultiplication.
                         */
                        rgba = 
                                ((255 * ((bgra >> 8) & 0xff) / a) << 24) |
                                ((255 * ((bgra >> 16) & 0xff) / a) << 16) |
                                ((255 * ((bgra >> 24) & 0xff) / a) << 8) |
                                a;

                buf[i] = GUINT32_TO_BE( rgba );
	}
}
