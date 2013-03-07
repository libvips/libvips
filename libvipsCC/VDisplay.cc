// Object part of VDisplay class

/*

    Copyright (C) 1991-2001 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <cstdlib>
#include <cstring>

#include <vips/vips.h>
#include <vips/internal.h>

#include <vips/vipscpp.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

VIPS_NAMESPACE_START

/* Refcounting stuff first.
 */

// Free an im_col_display
static void
free_display( im_col_display *d )
{
}

// Dupe an im_col_display
static im_col_display *
dup_display( im_col_display *in ) throw( VError )
{
	return( in );
}

// Remove lut
void VDisplay::refblock::cleanlut()
{
	if( luts ) {
		im_free( luts );
		luts = 0;
	}
}

// Remove attached things
void VDisplay::refblock::cleanref()
{
	if( disp && priv ) {
		free_display( disp );
		disp = 0;
		priv = 0;
	}
	cleanlut();
}

// Get ready to write to disp
void VDisplay::refblock::wready() throw( VError )
{
	cleanlut();
	if( !priv ) {
		disp = dup_display( disp );
		priv = 1;
	}
}

// Check that luts are up-to-date
void VDisplay::refblock::cluts() throw( VError )
{
}

VDisplay::~VDisplay()
{
	ref->nrefs--;
	if( !ref->nrefs ) 
		delete ref;
}

VDisplay &VDisplay::operator=( const VDisplay &a )
{ 
	ref->nrefs--;

	if( ref->nrefs > 0 ) 
		// Need fresh
		ref = new refblock;
	else 
		// Recycle old
		ref->cleanref();

	ref = a.ref; 
	ref->nrefs++; 
	
	return( *this ); 
}

VDisplay::VDisplay( const char *name ) throw( VError )
{
	// Install display
	ref = new refblock;
	ref->disp = NULL;
}

VDisplay::VDisplay()
{
	// Just use sRGB
	ref = new refblock;
	ref->disp = im_col_displays( 7 );
}

/*

Setters and getters. We used to have a lot of code of the form:
 
float &VDisplay::YCW()
	{ ref->wready(); return( ((im_col_display*)ref->disp)->d_YCW ); }

This should be split to separate setters/getters so we can exploit const. Too 
annoying to do this on such a useless class (I'm certain no one used these 
functions anyway), fix in vips8.

 */

VIPS_NAMESPACE_END

