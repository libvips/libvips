/* Convert 1 to 4-band 8 or 16-bit VIPS images to/from PNG.
 *
 * 19/12/11
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

int
im_vips2png( IMAGE *in, const char *filename )
{
	int compression; 
	int interlace; 

	char *p, *q;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	/* Extract write mode from filename and parse.
	 */
	im_filename_split( filename, name, mode );
	strcpy( buf, mode ); 
	p = &buf[0];
	compression = 6;
	interlace = 0;
	if( (q = im_getnextoption( &p )) ) 
		compression = atoi( q );
	if( (q = im_getnextoption( &p )) ) 
		interlace = atoi( q );

	return( vips_pngsave( in, name, 
		"compression", compression, "interlace", interlace, NULL ) );
}

int
im_vips2bufpng( IMAGE *in, IMAGE *out,
	int compression, int interlace, char **obuf, size_t *olen )
{
	if( vips_pngsave_buffer( in, (void **) obuf, olen, 
		"compression", compression, 
		"interlace", interlace, 
		NULL ) )
		return( -1 );
	im_add_callback( out, "close", 
		(im_callback_fn) vips_free, obuf, NULL ); 

	return( 0 );
}
