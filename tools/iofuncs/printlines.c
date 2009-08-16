/* @(#)  Prints the values of a file
 * @(#)  Result is printed in stderr output
 * @(#)
 * @(#)  Usage: printlines infile
 * @(#)  
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 03/08/1990
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

#include <vips/vips.h>

int
main( int argc, char **argv )
{
	IMAGE  *in;

	if ( (argc != 2)||(argv[1][0] == '-') )
		error_exit( "Usage:\n%s infile\n\n\
Image is printed in stderr\n", argv[0]);

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	if ((in = im_open(argv[1],"r")) == NULL)
		error_exit("Unable to open %s for input", argv[1]);

	if (im_printlines(in) == -1)
		error_exit("unable to im_printlines");

	im_close(in);

	return(0);
}
