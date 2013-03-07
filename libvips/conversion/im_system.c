/* im_system(): run a command on an image
 *
 * 7/3/00 JC
 *	- hacked it in
 * 21/10/02 JC
 *	- use mktemp() if mkstemp() is not available
 * 10/3/03 JC
 *	- out can be NULL
 * 23/12/04
 *	- use g_mkstemp()
 * 8/9/09
 * 	- add .v suffix (thanks Roland)
 * 	- use vipsbuf
 * 	- rewrite to make it simpler
 * 2/2/10
 * 	- gtkdoc
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

#define IM_MAX_STRSIZE (4096)

/**
 * im_system:
 * @im: image to run command on
 * @cmd: command to run
 * @out: stdout of command is returned here
 *
 * im_system() runs a command on an image, returning the command's output as a
 * string. The command is executed with popen(), the first '%%s' in the 
 * command being substituted for a filename.
 *
 * If the IMAGE is a file on disc, then the filename will be the name of the 
 * real file. If the image is in memory, or the result of a computation, 
 * then a new file is created in the temporary area called something like 
 * "vips_XXXXXX.v", and that filename given to the command. The file is 
 * deleted when the command finishes.
 *
 * See im_system_image() for details on how VIPS selects a temporary
 * directory.
 *
 * In all cases, @log must be freed with im_free().
 *
 * See also: im_system_image().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_system( IMAGE *im, const char *cmd, char **out )
{
	FILE *fp;

	if( !im_isfile( im ) ) {
		IMAGE *disc;

		if( !(disc = im__open_temp( "%s.v" )) )
			return( -1 );
		if( im_copy( im, disc ) ||
			im_system( disc, cmd, out ) ) {
			im_close( disc );
			return( -1 );
		}
		im_close( disc );
	}
	else if( (fp = im_popenf( cmd, "r", im->filename )) ) {
		char line[IM_MAX_STRSIZE];
		char txt[IM_MAX_STRSIZE];
		VipsBuf buf = VIPS_BUF_STATIC( txt );

		while( fgets( line, IM_MAX_STRSIZE, fp ) ) 
			if( !vips_buf_appends( &buf, line ) )
				break; 
		pclose( fp );

		if( out )
			*out = im_strdup( NULL, vips_buf_all( &buf ) );
	}

	return( 0 );
}
