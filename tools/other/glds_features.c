/* @(#)  Prints features of glds in stderr
 * @(#) Usage:  glds_features matrix 
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
#include <math.h>

#include <vips/vips.h>

int
main( int argc, char *argv[] )
{
	IMAGE *matrix;
	double fasm, fent, fmean, fcon;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	if( argc != 2 )
		error_exit( "usage: %s matrix_image", argv[0] );


	if( !(matrix = im_open(argv[1],"r")) )
		error_exit( "unable to open %s for input",
			argv[1] );

	if( im_glds_asm( matrix, &fasm ) )
		error_exit( "unable to im_glds_asm");

	if( im_glds_contrast( matrix, &fcon ) )
		error_exit( "unable to im_glds_contrast");

	if( im_glds_entropy( matrix, &fent ) )
		error_exit( "unable to im_glds_entropy");

	if( im_glds_mean( matrix, &fmean ) )
		error_exit( "unable to im_glds_mean");

	if( im_close( matrix ) )
		error_exit( "unable to close %s", argv[1]);

	printf( "glds: ASM=%f, ENT=%f, MEAN=%f, CON=%f\n",
		fasm, fent, fmean, fcon);

	return(0);
}
