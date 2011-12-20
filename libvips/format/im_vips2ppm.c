/* Write a ppm file.
 *
 * 20/12/11
 * 	- just a compat stub
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

#include <string.h>

#include <vips/vips.h>

int
im_vips2ppm( IMAGE *in, const char *filename )
{
	int ascii;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];

	/* Default to binary output ... much smaller.
	 */
	ascii = 0;

	/* Extract write mode from filename.
	 */
	im_filename_split( filename, name, mode );
	if( strcmp( mode, "" ) != 0 ) {
		if( im_isprefix( "binary", mode ) )
			ascii = 0;
		else if( im_isprefix( "ascii", mode ) )
			ascii = 1;
		else {
			im_error( "im_vips2ppm", 
				"%s", _( "bad mode string, "
					"should be \"binary\" or \"ascii\"" ) );
			return( -1 );
		}
	}

	return( vips_ppmsave( in, filename, "ascii", ascii, NULL ) ); 
}
