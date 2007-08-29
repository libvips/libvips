/* @(#) print error mesg on stderr and exit(1)
 * @(#) It also prints any additional error messages set by the routines 
 * @(#) 
 * @(#)  Usage:
 * @(#) void error_exit(variable_arg_list)
 *
 * Copyright: N. Dessipris
 * Written on: 19/03/1991
 * Modified on: 
 * 11/5/93 J.Cupitt
 *	- strange extra newlines removed - see im_errormsg()
 *	- strange tests removed
 * 28-4-99 JC
 *	- ansified
 * 2/8/06 
 * 	- print prgname
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
#include <stdarg.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

void 
error_exit( const char *fmt, ... )
{	
	va_list ap;

	fprintf( stderr, "%s: ", g_get_prgname() );

	va_start( ap, fmt );
	(void) vfprintf( stderr, fmt, ap );
	va_end( ap );

	fprintf( stderr, "\n" );
	fprintf( stderr, "%s", im_errorstring() );

	exit( 1 );
}
