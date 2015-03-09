/* vips7 compat stub for vips_dzsave()
 *
 * 11/6/13
 * 	- from im_vips2tiff()
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

/* Turn on IM_REGION_ADDR() range checks, don't delete intermediates.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

int
im_vips2dz( IMAGE *in, const char *filename )
{
	char *p, *q;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	int i;
	VipsForeignDzLayout layout = VIPS_FOREIGN_DZ_LAYOUT_DZ; 
	char *suffix = ".jpeg";
	int overlap = 0;
	int tile_size = 256;
	VipsForeignDzDepth depth = VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL; 
	gboolean centre = FALSE;
	VipsAngle angle = VIPS_ANGLE_D0; 

	/* We can't use im_filename_split() --- it assumes that we have a
	 * filename with an extension before the ':', and filename here is
	 * actually a dirname.
	 *
	 * Just split on the first ':'.
	 */
	im_strncpy( name, filename, FILENAME_MAX ); 
	if( (p = strchr( name, ':' )) ) {
		*p = '\0';
		im_strncpy( mode, p + 1, FILENAME_MAX ); 
	}

	strcpy( buf, mode ); 
	p = &buf[0];

	if( (q = im_getnextoption( &p )) ) {
		if( (i = vips_enum_from_nick( "im_vips2dz", 
			VIPS_TYPE_FOREIGN_DZ_LAYOUT, q )) < 0 ) 
			return( -1 );
		layout = i;
	}

	if( (q = im_getnextoption( &p )) ) 
		suffix = g_strdup( q );
	if( (q = im_getnextoption( &p )) ) 
		overlap = atoi( q ); 
	if( (q = im_getnextoption( &p )) ) 
		tile_size = atoi( q ); 

	if( (q = im_getnextoption( &p )) ) {
		if( (i = vips_enum_from_nick( "im_vips2dz", 
			VIPS_TYPE_FOREIGN_DZ_DEPTH, q )) < 0 )
			return( -1 );
		depth = i;
	}

	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "cen", q ) ) 
			centre = TRUE;
	}

	if( (q = im_getnextoption( &p )) ) {
		if( (i = vips_enum_from_nick( "im_vips2dz", 
			VIPS_TYPE_ANGLE, q )) < 0 )
			return( -1 );
		angle = i;
	}

	if( vips_dzsave( in, name,
		"layout", layout,
		"suffix", suffix,
		"overlap", overlap,
		"tile_size", tile_size,
		"depth", depth,
		"centre", centre,
		"angle", angle,
		NULL ) )
		return( -1 );

	return( 0 );
}
