/* common jpeg definitions
 *
 * 24/11/11
 * 	- from im_vips2jpeg.c
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
#include <string.h>
#include <setjmp.h>

#include <vips/vips.h>

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#include "jpeg.h"

/* New output message method - send to VIPS.
 */
void
vips__new_output_message( j_common_ptr cinfo )
{
	char buffer[JMSG_LENGTH_MAX];

	(*cinfo->err->format_message)( cinfo, buffer );
	vips_error( "VipsFile*Jpeg", _( "%s" ), buffer );

#ifdef DEBUG
	printf( "jpeg.c: new_output_message: \"%s\"\n", buffer );
#endif /*DEBUG*/
}

/* New error_exit handler.
 */
void
vips__new_error_exit( j_common_ptr cinfo )
{
	ErrorManager *eman = (ErrorManager *) cinfo->err;

#ifdef DEBUG
	printf( "jpeg.c: new_error_exit\n" );
#endif /*DEBUG*/

	/* Close the fp if necessary.
	 */
	if( eman->fp ) {
		(void) fclose( eman->fp );
		eman->fp = NULL;
	}

	/* Send the error message to VIPS. This method is overridden above.
	 */
	(*cinfo->err->output_message)( cinfo );

	/* Jump back.
	 */
	longjmp( eman->jmp, 1 );
}

