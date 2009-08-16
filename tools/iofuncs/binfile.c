/* @(#)  Command which adds a vasari header to a binary file
 * @(#)  The user must ensure that the size of the file is correct
 * @(#)
 * @(#)  Usage: binfile infile outfile xs ys bands
 * @(#)  
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 31/07/1991
 * Modified on: 
 * 2/2/95 JC
 *	- ANSIfied
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

#include <vips/vips.h>

int
main( int argc, char **argv )
{
	IMAGE *bin, *out;
	int xs, ys, bands, offset;

	if( argc != 7 )
		error_exit( "usage: %s infile outfile xsize ysize bands offset",
			argv[0] );

	xs = atoi(argv[3]);
	ys = atoi(argv[4]);
	bands = atoi(argv[5]);
	offset = atoi(argv[6]);

	if( im_init_world( argv[0] ) )
		error_exit( "unable to start VIPS" );

	if( !(out = im_open( argv[2], "w" )) )
		error_exit( "unable to open %s for output", argv[2] );
	if( !(bin = im_binfile( argv[1], xs, ys, bands, offset )) )
		error_exit( "unable to im_binfile" );
	if( im_copy( bin, out ) )
		error_exit( "unable to copy to %s", argv[2] );

	im_close( out );
	im_close( bin );

	return( 0 );
}
