/* Use one mosiaced file to mosaic another set of images.
 *
 * 1/11/01 JC
 *	- from global_balance
 * 25/02/02 JC
 *	- detect size change
 * 10/4/06
 * 	- spot file-not-found
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

/* Define for debug output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/transform.h>

#include "merge.h"
#include "global_balance.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct _RemosaicData {
	const char *old_str;
	const char *new_str;
	int new_len;
	int old_len;
} RemosaicData;

static IMAGE *
remosaic( JoinNode *node, RemosaicData *rd )
{
	SymbolTable *st = node->st;
	IMAGE *im = node->im;

	IMAGE *out;
	char filename[FILENAME_MAX];
	char *p;

	if( !im ) {
		im_error( "im_remosaic", _( "file \"%s\" not found" ), 
			node->name );
		return( NULL );
	}

	/* Remove substring rd->old_str from in->filename, replace with
	 * rd->new_str.
	 */
	im_strncpy( filename, im->filename, FILENAME_MAX );
	if( (p = im_strrstr( filename, rd->old_str )) ) {
		int offset = p - &filename[0];

		im_strncpy( p, rd->new_str, FILENAME_MAX - offset );
		im_strncpy( p + rd->new_len,
			im->filename + offset + rd->old_len, 
			FILENAME_MAX - offset - rd->new_len );
	}

#ifdef DEBUG
	printf( "im_remosaic: filename \"%s\" -> \"%s\"\n", 
		im->filename, filename );
#endif /*DEBUG*/

	if( !(out = im__global_open_image( st, filename )) ) 
		return( NULL );

	if( out->Xsize != im->Xsize || out->Ysize != im->Ysize ) {
		im_error( "im_remosaic", 
			_( "substitute image \"%s\" is not "
				"the same size as \"%s\"" ), 
			filename, im->filename );
		return( NULL );
	}

	return( out );
}

int
im_remosaic( IMAGE *in, IMAGE *out, const char *old_str, const char *new_str )
{
	SymbolTable *st;
	RemosaicData rd;

	if( !(st = im__build_symtab( out, SYM_TAB_SIZE )) ||
		im__parse_desc( st, in ) )
		return( -1 );

	/* Re-make mosaic.
	 */
	rd.old_str = old_str;
	rd.new_str = new_str;
	rd.new_len = strlen( new_str );
	rd.old_len = strlen( old_str );
	if( im__build_mosaic( st, out, (transform_fn) remosaic, &rd ) )
		return( -1 );

	return( 0 );
}
