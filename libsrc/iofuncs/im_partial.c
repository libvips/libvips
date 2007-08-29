/* @(#) im_partial: initialise a partial IMAGE. Just set im->dtype.
 * @(#)
 * @(#) IMAGE *
 * @(#) im_partial( file_name )
 * @(#) char *file_name;
 * @(#)
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
im_partial( const char *filename )
{	
	IMAGE *im = im_init( filename );

	if( !im )
		return(NULL);
	im->dtype = IM_PARTIAL;

	/* No need to set demand style - im_demand_hint() from application
	 * will do this.
	 */

	return( im );
}
