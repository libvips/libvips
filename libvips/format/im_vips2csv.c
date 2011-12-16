/* Write a csv file.
 * 
 * 16/12/11
 * 	- just a stub
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

#include <vips/vips.h>

int 
im_vips2csv( IMAGE *in, const char *filename )
{
	char *separator = "\t";

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q, *r;

	/* Parse mode string.
	 */
	im_filename_split( filename, name, mode );
	p = &mode[0];
	while( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "sep", q ) && (r = im_getsuboption( q )) )
			separator = r;
	}

	if( vips_csvsave( in, name, "separator", separator, NULL ) )
		return( -1 );

	return( 0 );
}
