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

/* Run a command on an IMAGE ... copy to tmp (if necessary), run 
 * command on it, unlink (if we copied), return stdout from command.
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
