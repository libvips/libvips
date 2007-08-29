/* Time execution of pipelines.
 * 
 * 20/7/93 JC
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
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/time.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Allocate a new time struct and fill in start values.
 */
static int
new_time( IMAGE *im )
{
	struct time_info *tim = IM_NEW( im, struct time_info );

	if( !tim )
		return( -1 );

	if( im->time ) {
		im_errormsg( "new_time: sanity failure" );
		return( -1 );
	}

	tim->im = im;
	tim->start = time( NULL );
	tim->run = 0;
	tim->eta = 0;
	tim->tpels = (gint64) im->Xsize * im->Ysize;
	tim->npels = 0;
	tim->percent = 0;
	im->time = tim;

	return( 0 );
}

/* A new tile has been computed. Update time_info.
 */
static int
update_time( struct time_info *tim, int w, int h )
{
	float prop;

	tim->run = time( NULL ) - tim->start;
	tim->npels += w * h;
	prop = (float) tim->npels / (float) tim->tpels;
	tim->percent = 100 * prop;
	if( prop > 0 ) 
		tim->eta = (1.0 / prop) * tim->run - tim->run;

	return( 0 );
}

/* Handle eval callbacks. w and h are the size of the tile we made this time.
 */
int
im__handle_eval( IMAGE *im, int w, int h )
{
	if( im->evalfns ) {
		if( !im->time )
			if( new_time( im ) )
				return( -1 );
		if( update_time( im->time, w, h ) )
			return( -1 );
		
		if( im__trigger_callbacks( im->evalfns ) )
			return( -1 );
	}

	return( 0 );
}
