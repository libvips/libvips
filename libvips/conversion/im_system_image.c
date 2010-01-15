/* im_system_image(): run a command on an image, get an image result
 *
 * 8/1/09
 * 	- from im_system()
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define IM_MAX_STRSIZE (4096)

static int
system_image( IMAGE *im, 
	IMAGE *in_image, char *out_name, const char *cmd_format, 
	char **log ) 
{
	const char *in_name = in_image->filename;
	FILE *fp;
	char line[IM_MAX_STRSIZE];
	char txt[IM_MAX_STRSIZE];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int result;

	if( im_copy( im, in_image ) ||
		!(fp = im_popenf( cmd_format, "r", in_name, out_name )) ) 
		return( -1 );

	while( fgets( line, IM_MAX_STRSIZE, fp ) ) 
		if( !vips_buf_appends( &buf, line ) )
			break; 

	result = pclose( fp );

	if( log )
		*log = im_strdup( NULL, vips_buf_all( &buf ) );

	return( result );
}

/**
 * im_system_image:

   Run a command on an image, returning a new image. Eg.:

   im_system_image A2 "%s.jpg" "%s.jpg" "convert %s -swirl 45 %s"

 Actions:

- create two temporary file names using the passed format strings to set type
= expand the command, using the two expanded filenames
- write the image to the first filename
- call system() on the expanded command
- capture stdout into log
- delete the temp input file
- open the output image (the output file will be auto deleted when this 
  IMAGE is closed.
- return the output filename, or NULL if the command failed (log is still
  set in this case)

  */

IMAGE *
im_system_image( IMAGE *im, 
	const char *in_format, const char *out_format, const char *cmd_format, 
	char **log )
{
	IMAGE *in_image;
	char *out_name;
	IMAGE *out;

	if( log )
		*log = NULL;

	if( !(in_image = im__open_temp( in_format )) )
		return( NULL );
	if( !(out_name = im__temp_name( out_format )) ) {
		im_close( in_image );
		return( NULL );
	}

	if( system_image( im, in_image, out_name, cmd_format, log ) ) {
		im_close( in_image );
		g_free( out_name );

		return( NULL );
	}
	im_close( in_image );

	if( !(out = im_open( out_name, "r" )) ) {
		g_free( out_name );

		return( NULL );
	}
	if( im_add_postclose_callback( out, 
		(im_callback_fn) unlink, out->filename, NULL ) ) {
		g_free( out_name );
		im_close( out );
		g_unlink( out_name );

		return( NULL );
	}
	g_free( out_name );

	return( out );
}
