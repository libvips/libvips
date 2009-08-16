/* @(#) im_setbuf: initialise a buffer IMAGE
 * @(#) Initialise the data pointer of the image descriptor to an arbitrary 
 * @(#) non NULL value and copies the file_name onto the filename of the 
 * @(#) image structure. 
 * @(#)
 * @(#) Right call:
 * @(#) IMAGE  *im_setbuf(file_name)
 * @(#) char *file_name;
 * @(#)
 *
 * Copyright: Nicos Dessipris
 * Written on: 13/02/1990
 * Modified on :  25/04/1990 KM, 20/03/1991 ND
 * 16/4/93 J.Cupitt
 *	- support for type field added
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

IMAGE *
im_setbuf( const char *file_name )
{	
	IMAGE *im;

	if( !(im = im_init( file_name )) ) 
		return( NULL );
	im->dtype = IM_SETBUF;

	/* Set demand style. Allow the most permissive sort.
	 */
	im->dhint = IM_ANY;

	return( im );
}
