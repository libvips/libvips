/* @(#)  
 * @(#) int 
 * @(#) im_updatehist( IMAGE *out, const char *name, int argc, char *argv[] )
 * @(#) 
 * @(#)  Returns either 0 (success) or -1 (fail)
 * @(#) 
 *
 * Copyright: Nicos Dessipris
 * Written on: 16/01/1990
 * Modified on : 28/10/1992 J. Cupitt
 *	- now calls im_histlin, much simpler
 *	- many bugs in old version ...
 * 22/8/05
 * 	- pass argv0 separately
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
#include <time.h>

#include <vips/vips.h>
#include <vips/buf.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define IM_MAX_LINE (4096)

int 
im_updatehist( IMAGE *out, const char *name, int argc, char *argv[] )
{	
	int i;
	char txt[IM_MAX_LINE];
	im_buf_t buf;

	im_buf_init_static( &buf, txt, IM_MAX_LINE );
	im_buf_appends( &buf, name );

	for( i = 0; i < argc; i++ ) {
		im_buf_appends( &buf, " " );
		im_buf_appends( &buf, argv[i] );
	}

	if( im_histlin( out, "%s", im_buf_all( &buf ) ) ) 
		return( -1 );

	return( 0 );
}
