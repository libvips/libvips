/* rename.c --- wrappers for various renamed functions
 *
 * 20/9/09
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

#include <vips/vips.h>
#include <vips/deprecated.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_remainder_vec( in, out, n, c ) );
}

int 
im_and_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_andimage_vec( in, out, n, c ) ); 
}

int 
im_or_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_orimage_vec( in, out, n, c ) ); 
}

int 
im_eor_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_eorimage_vec( in, out, n, c ) ); 
}

int 
im_andconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_andimageconst( in, out, c ) ); 
}

int 
im_orconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_orimageconst( in, out, c ) );
}

int 
im_eorconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_eorimageconst( in, out, c ) );
}

void 
im_errormsg( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_verror( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_verrormsg( const char *fmt, va_list ap )
{	
	im_verror( "untranslated", fmt, ap );
}

void
im_errormsg_system( int err,  const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_verror_system( err, "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_diagnostics( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_vdiag( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_warning( const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_vwarn( "untranslated", fmt, ap );
	va_end( ap );
}

int 
im_affine( IMAGE *in, IMAGE *out, 
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh )
{
	return( im_affinei( in, out, 
		vips_interpolate_bilinear_static(), 
		a, b, c, d, dx, dy, 
		ox, oy, ow, oh ) );
}
