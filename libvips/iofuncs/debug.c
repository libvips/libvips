/* debug.c: support for debugging
 *
 * 24/10/95 JC
 *	- first version
 * 24/2/05
 *	- print more mem allocation info
 * 2/10/09
 * 	- im_image_sanity() moved here
 * 	- im_printdesc() moved here
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
#include <string.h>

#include <vips/vips.h>
#include <vips/util.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Prettyprint various header fields. Just for vips7 compat, use
 * VIPS_ENUM_VALUE() instead.
 */
const char *im_Type2char( VipsInterpretation type ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_INTERPRETATION, type ) ); }
const char *im_BandFmt2char( VipsBandFormat format ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_BAND_FORMAT, format ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_CODING, coding ) ); }
const char *im_dtype2char( VipsImageType n ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_IMAGE_TYPE, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, style ) ); }

int im_char2Type( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_INTERPRETATION, str ) ); }
int im_char2BandFmt( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_BAND_FORMAT, str ) ); }
int im_char2Coding( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_CODING, str ) ); }
int im_char2dtype( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_IMAGE_TYPE, str ) ); }
int im_char2dhint( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_DEMAND_STYLE, str ) ); }

/* Totally useless now.
 */
const char *im_Compression2char( int n ) { return( "NONE" ); }
int im_char2Compression( const char *str ) { return( -1 ); }

/* Print something about all current objects.
 */
void
im__print_all( void )
{
	vips_object_map( (VSListMap2Fn) vips_object_print, NULL, NULL );
}

int 
im_image_sanity( IMAGE *im )
{
	return( 0 );
}

void
im_image_sanity_all( void )
{
}
