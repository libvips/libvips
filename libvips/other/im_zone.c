/* square zone plate of size
 *
 * N. Dessipris 01/02/1991
 *
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
 * 30/8/95 JC
 *	- modernized
 *	- memory leaks fixed
 *	- split into im_zone() and im_fzone()
 * 1/2/11
 * 	- gtk-doc
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_fzone:
 * @out: output image
 * @size: image size
 *
 * Create a one-band float image of size @size by @size pixels of a zone
 * plate. Pixels are in [-1, +1].
 *
 * See also: im_grey(), im_make_xy(), im_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_fzone( IMAGE *out, int size )
{
	int x, y;
	int i, j;

	float *buf;
	const int size2 = size/2;

	/* Check args.
	 */
	if( im_outcheck( out ) )
		return( -1 );
	if( size <= 0 || (size % 2) != 0 ) {
		im_error( "im_zone", "%s", 
			_( "size must be even and positive" ) );
		return( -1 );
	}

	/* Set up output out.
	 */
        im_initdesc( out, size, size, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( out ) )
                return( -1 );

	/* Create output buffer.
	 */
        if( !(buf = IM_ARRAY( out, size, float )) )
                return( -1 );

	/* Make zone plate.
	 */
	for( y = 0, j = -size2; j < size2; j++, y++ ) {
		for( x = 0, i = -size2; i < size2; i++, x++ )
			buf[x] = cos( (IM_PI / size) * (i * i + j * j) );
		if( im_writeline( y, out, (PEL *) buf ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * im_zone:
 * @out: output image
 * @size: image size
 *
 * Create a one-band uchar image of size @size by @size pixels of a zone
 * plate. Pixels are in [0, 255].
 *
 * See also: im_grey(), im_make_xy(), im_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_zone( IMAGE *im, int size )
{
	IMAGE *t[2];

	/* Change range to [0,255].
	 */
	if( im_open_local_array( out, t, 2, "im_grey", "p" ) ||
		im_fzone( t[0], size ) || 
		im_lintra( 127.5, t[0], 127.5, t[1] ) ||
		im_clip2fmt( t[1], im, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}
