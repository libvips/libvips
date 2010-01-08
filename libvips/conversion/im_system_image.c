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

#ifdef OS_WIN32
#define popen(b,m) _popen(b,m)
#define pclose(f) _pclose(f)
#endif /*OS_WIN32*/

static int
system_image( IMAGE *im, 
	const char *in_name, const char *out_name, const char *cmd_format, 
	char **log ) 
{
	IMAGE *disc;
	FILE *fp;
	char line[IM_MAX_STRSIZE];
	char txt[IM_MAX_STRSIZE];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int result;

	if( !(disc = im_open( in_name, "w" )) ) 
		return( -1 );
	if( im_copy( im, disc ) ) {
		im_close( im );
		g_unlink( in_name );

		return( -1 );
	}
	im_close( im );

	if( !(fp = im_popenf( cmd_format, "r", in_name, out_name )) ) {
		g_unlink( in_name );

		return( -1 );
	}

	while( fgets( line, IM_MAX_STRSIZE, fp ) ) 
		if( !vips_buf_appends( &buf, line ) )
			break; 

	result = pclose( fp );

	g_unlink( in_name );

	if( log )
		*log = im_strdup( NULL, vips_buf_all( &buf ) );

	return( result );
}

/* 

   Run a command on an image, returning a new image.

   "mycommand --dostuff %s -o %s"

   have separate format strings for input and output?

   "%s.jpg"

 Actions:

- create two empty temporary files
- write the image to the first
- call system() on the expanded command
- capture stdout/stderr into log
- delete the temp input file
- return the output filename, or NULL if the command failed (log is still
  set in this case)

  The caller would open the output file, either with im_open(), or with it's
  own system (nip2 has it's own open file thing to give progress feedback and
  use disc for format conversion), and be responsible for deleting the temp
  output file at some point.
 
  */

char *
im_system_image( IMAGE *im, 
	const char *in_format, const char *out_format, const char *cmd_format, 
	char **log )
{
	char *in_name;
	char *out_name;

	if( log )
		*log = NULL;

	in_name = im__temp_name( in_format );
	out_name = im__temp_name( in_format );

	if( !in_name || 
		!out_name ||
		system_image( im, in_name, out_name, cmd_format, log ) ) {
		g_free( in_name );
		g_free( out_name );

		return( NULL );
	}
	g_free( in_name );

	return( out_name );
}
