/* @(#) im_openout: associates an IMAGE with an image file for output
 * @(#) IMAGE should be closed with im_close()
 * @(#) Usage:
 * @(#) IMAGE *im_openout(file_name)
 * @(#) char *file_name;
 * @(#)
 * @(#) Returns *IMAGE or NULL on error.
 *
 * Copyright: Nicos Dessipris
 * Written on: 13/02/1990
 * Modified on :  26/04/1990 by KM
 * 16/4/93 JC
 *	- uses new init, type style
 *	- memory leak fixed
 * 11/5/93 JC
 *	- newer im_init() style
 * 23/10/98 JC
 *	- new BINARY_OPEN define
 * 4/7/01 JC
 *	- delay open() until im_setupout()
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
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

IMAGE *
im_openout( const char *file_name )
{	
	IMAGE *image;

	if( !(image = im_init( file_name )) ) 
		return( NULL );
	image->dtype = IM_OPENOUT;

	return( image );
}
