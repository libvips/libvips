/* @(#)  Creates a cooourrence matrix from an image
 * @(#) Usage:  cooc image matrix xpos ypos xsize ysize dx dy flag
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: N. Dessipris
 * Written on: 26/03/1991
 * Modified on:
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

int
main( int argc, char **argv )
{
	IMAGE *image, *matrix;
	int xpos, ypos, xsize, ysize, dx, dy, flag;

	if (argc != 10)
		error_exit("Usage:\n\
%s image matrix xpos ypos xsize ysize dx dy flag\n\
WARNING: The program overwrites the output file if the owner has rw access.",
argv[0]);

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	xpos = atoi(argv[3]);
	ypos = atoi(argv[4]);
	xsize = atoi(argv[5]);
	ysize = atoi(argv[6]);
	dx = atoi(argv[7]);
	dy = atoi(argv[8]);
	flag = atoi(argv[9]);

	if ( (image = im_open(argv[1],"r")) == NULL )
		error_exit("Unable to open %s for input", argv[1]);

	if ( (matrix = im_open(argv[2],"w")) == NULL )
		error_exit("Unable to open %s for output", argv[2]);

	if ( im_cooc_matrix(image, matrix, xpos, ypos, xsize, ysize,
		dx, dy, flag) == -1 )
		error_exit("Unable to im_cooc_matrix");

	if ( im_updatehist(matrix, argv[0], argc - 1, argv + 1) == -1)
		error_exit("Unable to update history");

	if ( ( im_close( image ) == -1 )||( im_close( matrix ) == -1 ) )
		error_exit("Unable to close %s or %s",argv[1], argv[2]);

	return(0);
}
