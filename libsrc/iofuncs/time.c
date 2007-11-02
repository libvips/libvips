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

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int
im__time_destroy( IMAGE *im )
{
	if( im->time ) {
		g_timer_destroy( im->time->start );
		im_free( im->time );
		im->time = NULL;
	}

	return( 0 );
}

/* Attach a new time struct and fill in start values.
 */
int
time_add( IMAGE *im )
{
	im_time_t *time;

	if( im__time_destroy( im ) ||
		!(time = IM_NEW( NULL, im_time_t )) )
		return( -1 );

	time->im = im;
	time->start = g_timer_new();
	time->run = 0;
	time->eta = 0;
	time->tpels = (gint64) im->Xsize * im->Ysize;
	time->npels = 0;
	time->percent = 0;
	im->time = time;

	return( 0 );
}

/* A new tile has been computed. Update time_info.
 */
static int
update_time( im_time_t *time, int w, int h )
{
	float prop;

	time->run = g_timer_elapsed( time->start, NULL );
	time->npels += w * h;
	prop = (float) time->npels / (float) time->tpels;
	time->percent = 100 * prop;
	if( prop > 0 ) 
		time->eta = (1.0 / prop) * time->run - time->run;

	return( 0 );
}

/* Handle eval callbacks. w and h are the size of the tile we made this time.
 */
int
im__handle_eval( IMAGE *im, int w, int h )
{
	if( im->evalfns ) {
		if( !im->time )
			if( time_add( im ) )
				return( -1 );
		if( update_time( im->time, w, h ) )
			return( -1 );
		
		if( im__trigger_callbacks( im->evalfns ) )
			return( -1 );
	}

	return( 0 );
}
