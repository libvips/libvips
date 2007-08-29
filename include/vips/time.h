/* Definitions for time struct.
 *
 * J.Cupitt, 8/4/93
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

#ifndef IM_TIME_H
#define IM_TIME_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /*HAVE_SYS_TIME_H*/

/* Struct we keep a record of execution time in. Passed to eval callback, so
 * it can assess progress.
 */
struct time_info {
	IMAGE *im;		/* Image we are part of */
	time_t start;		/* Start time, in seconds */
	int run;		/* Time we have been running */
	int eta;		/* Estimated seconds of computation left */
	gint64 tpels;		/* Number of pels we expect to calculate */
	gint64 npels;		/* Number of pels calculated so far */
	int percent;		/* Percent complete */
};

extern int im__handle_eval( IMAGE *im, int w, int h );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_TIME_H*/
