/* Convert 8-bit VIPS images to/from JPEG.
 *
 * 30/11/11
 * 	- now just a stub calling the new system
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

/*
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

int
im_vips2jpeg( IMAGE *in, const char *filename )
{
	int qfac = 75; 

	/* profile has to default to NULL, meaning "no param". If we default
	 * to "none" we will not attach the profile from the metadata.
	 */
	char *profile = NULL;

	char *p, *q;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	/* Parse mode from filename.
	 */
	im_filename_split( filename, name, mode );
	strcpy( buf, mode ); 
	p = &buf[0];
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 )
			qfac = atoi( mode );
	}
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 ) 
			profile = q;
	}
	if( (q = im_getnextoption( &p )) ) {
		im_error( "im_vips2jpeg", 
			_( "unknown extra options \"%s\"" ), q );
		return( -1 );
	}

	return( vips_jpegsave( in, name, 
		"Q", qfac, "profile", profile, NULL ) );
}

int
im_vips2bufjpeg( IMAGE *in, IMAGE *out, int qfac, char **obuf, int *olen )
{
	size_t len;

	if( vips_jpegsave_buffer( in, (void **) obuf, &len, "Q", qfac, NULL ) )
		return( -1 );
	im_add_callback( out, "close", 
		(im_callback_fn) vips_free, obuf, NULL ); 

	if( olen )
		*olen = len;

	return( 0 );
}

int
im_vips2mimejpeg( IMAGE *in, int qfac )
{
	return( vips_jpegsave_mime( in, "Q", qfac, NULL ) ); 
}
