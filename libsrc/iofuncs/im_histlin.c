/* @(#)  Appends one line of history consisting of a buffer of data,
 * @(#) time, history and CR in history section of the image descriptor
 * @(#)  The history variable list must be declared properly
 * @(#) by the calling function
 * @(#)
 * @(#) int im_histlin(variable_list)
 * @(#)	      (variable_list) is (imagedescriptor, format, arg1, arg2, ...)
 * @(#) format, arg1, arg2, ... are the same as in printf
 * @(#) 
 * @(#)  Returns either 0 (success) or -1 (fail)
 * @(#) 
 *
 * Copyright: Nicos Dessipris
 * Written on: 16/01/1990
 * Modified on : 21/03/1991
 * 28/10/92 JC
 *	- if Hist is NULL, no longer returns error code. Now makes a history 
 *	  line (just the file name) and continues
 *	- does not overwrite the end of strdup buffers any more!
 *	- bugs in calls to time/ctime fixed
 *	- no longer free's ctime's static buffer!
 *	- frees old Hist correctly
 * 22/12/94
 *	- ANSIfied with stdarg
 * 2/9/05
 * 	- no more first line of Hist means something special nonsense
 * 4/1/07
 * 	- added im_history_get()
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_histlin( IMAGE *im, const char *fmt, ... )
{
	va_list args;
	char line[4096];
	time_t timebuf;

	/* Format command. -40, to leave 26 for the ctime, three for the # and
	 * a bit.
	 */
	va_start( args, fmt );
	(void) im_vsnprintf( line, 4096 - 40, fmt, args );
	va_end( args );
	strcat( line, " # " );

	/* Add the date. ctime always attaches a '\n', gah.
	 */
	time( &timebuf );
	strcat( line, ctime( &timebuf ) );
	line[strlen( line ) - 1] = '\0';

#ifdef DEBUG
	printf( "im_histlin: adding:\n\t%s\nto history on image %p\n", 
		line, im );
#endif /*DEBUG*/

	im->history_list = g_slist_append( im->history_list, 
		im__gvalue_ref_string_new( line ) );

	return( 0 );
}

/* Read an image's history.
 */
const char *
im_history_get( IMAGE *im )
{
	if( !im->Hist )
		im->Hist = im__gslist_gvalue_get( im->history_list );

	return( im->Hist ? im->Hist : "" );
}
