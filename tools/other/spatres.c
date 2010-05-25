/* @(#)  Reduces the spatial resolution of an image by increasing the 
 * @(#) pixel size
 * @(#)
 * @(#)  Usage: spatres in out step
 * @(#)  
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 27/03/1991
 * Modified on : 
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

int
main( int argc, char **argv )
{
	IMAGE *in, *out;
	int step = 0;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

	if ( (argc != 4)||(argv[1][0] == '-') )
		error_exit(
		"Usage:\n%s in out step\n\n\
WARNING: The program destroys the opfile if the owner has rw access on it.",
		argv[0]);

	step = atoi(argv[3]);

	if ((in= im_open(argv[1],"r")) == NULL)
		error_exit("Unable to open %s for input", argv[1]);

	if ( (out=im_open(argv[2],"w")) == NULL )
		error_exit("Unable to open %s", argv[2]);

	if ( im_spatres(in, out, step) == -1)
		error_exit("Unable to im_spatres");

	if ( im_updatehist(out, argv[0], argc - 1, argv + 1) == -1)
		error_exit("Unable to update history");

	if ( (im_close(in) == -1)||(im_close(out) == -1) )
		error_exit("unable to close %s or %s",argv[1],argv[2]);

	return(0);
}
