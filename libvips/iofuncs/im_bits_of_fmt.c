/* Return number of bits of band format or -1 on error. 
 * 
 * 02/06/05 JF
 *     - original code
 * 12/1/06
 * 	- use a table
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static const int bits[] = {
	IM_BBITS_BYTE,
	IM_BBITS_BYTE,
	IM_BBITS_SHORT,
	IM_BBITS_SHORT,
	IM_BBITS_INT,
	IM_BBITS_INT,
	IM_BBITS_FLOAT,
	IM_BBITS_COMPLEX,
	IM_BBITS_DOUBLE,
	IM_BBITS_DPCOMPLEX
};

/* Return number of pel bits for band format, or -1 on error.
 */
int 
im_bits_of_fmt( VipsBandFmt fmt )
{
	return( fmt < 0 || fmt > IM_BANDFMT_DPCOMPLEX ?
		im_error( "im_bits_of_fmt", 
			_( "unsupported band format: %d" ), fmt ),
		-1 :
		bits[fmt] );
}
