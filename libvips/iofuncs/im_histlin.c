/* history handling
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

#define IM_MAX_LINE (4096)

/**
 * im_histlin:
 * @im: add history liine to this image
 * @fmt: printf() format string
 * @Varargs: arguments to format string
 *
 * Add a line to the image history. The @fmt and arguments are expanded, the
 * date and time is appended prefixed with a hash character, and the whole
 * string is appended to the image history and terminated with a newline.
 *
 * For example:
 *
 * |[
 * im_histlin( im, "vips im_invert %s %s", in->filename, out->filename );
 * ]|
 *
 * Might add the string
 *
 * |[
 * "vips im_invert /home/john/fred.v /home/john/jim.v # Fri Apr  3 23:30:35
 * 2009\n"
 * ]|
 *
 * VIPS operations don't add history lines for you because a single action at 
 * the application level might involve many VIPS operations. History must be
 * recorded by the application.
 *
 * See also: im_updatehist().
 *
 * Returns: 0 on success, -1 on error.
 */
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

/**
 * im_updatehist:
 * @out: image to attach history line to
 * @name: program name
 * @argc: number of program arguments
 * @argv: program arguments
 *
 * Formats the name/argv as a single string and calls im_histlin(). A
 * convenience function for command-line prorams.
 *
 * See also: im_history_get().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_updatehist( IMAGE *out, const char *name, int argc, char *argv[] )
{	
	int i;
	char txt[IM_MAX_LINE];
	VipsBuf buf = VIPS_BUF_STATIC( txt );

	vips_buf_appends( &buf, name );

	for( i = 0; i < argc; i++ ) {
		vips_buf_appends( &buf, " " );
		vips_buf_appends( &buf, argv[i] );
	}

	if( im_histlin( out, "%s", vips_buf_all( &buf ) ) ) 
		return( -1 );

	return( 0 );
}

/**
 * im_history_get:
 * @im: get history from here
 *
 * This function reads the image history as a C string. The string is owned
 * by VIPS and must not be freed.
 *
 * VIPS tracks the history of each image, that is, the sequence of operations
 * that generated that image. Applications built on VIPS need to call
 * im_histlin() for each action they perform setting the command-line
 * equivalent for the action.
 *
 * See also: im_histlin().
 *
 * Returns: The history of @im as a C string. Do not free!
 */
const char *
im_history_get( IMAGE *im )
{
	if( !im->Hist )
		im->Hist = im__gslist_gvalue_get( im->history_list );

	return( im->Hist ? im->Hist : "" );
}
