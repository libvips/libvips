/* @(#) Creates a pattern showing the simultaneous contrast
 * @(#) Usage:  simcontr file xsize ysize 
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
#include <locale.h>

#include <vips/vips.h>
#include <vips/internal.h>

int
main( int argc, char **argv )
{
	IMAGE *image;
	int xsize, ysize;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

	if (argc != 4)
		error_exit("Usage:\n%s file xsize ysize\n\n\
WARNING: The program overwrites the output file if the owner has rw access.",
argv[0]);

	xsize = atoi(argv[2]);
	ysize = atoi(argv[3]);


	if ( (image = im_openout(argv[1])) == NULL )
		error_exit("Unable to open %s for output", argv[1]);

	if ( im_simcontr(image, xsize, ysize) == -1 )
		error_exit("Unable to im_simcontr");

	if ( im_updatehist(image, argv[0], argc - 1, argv + 1) == -1)
		error_exit("Unable to update history");

	if ( im_close( image ) == -1 )
		error_exit("Unable to close %s", argv[1]);

	return(0);
}
