/* Error handling.
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_ERROR_H
#define VIPS_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

const char *vips_error_buffer( void );
void vips_error_clear( void );

void vips_error( const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
void vips_verror( const char *domain, const char *fmt, va_list ap );
void vips_error_system( int err, const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 3, 4)));
void vips_verror_system( int err, const char *domain, 
	const char *fmt, va_list ap );
void vips_error_g( GError **error );
void vips_warn( const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
void vips_vwarn( const char *domain, const char *fmt, va_list ap );
void vips_diag( const char *domain, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
void vips_vdiag( const char *domain, const char *fmt, va_list ap );

void vips_error_exit( const char *fmt, ... )
	__attribute__((noreturn, format(printf, 1, 2)));

int vips_check_uncoded( const char *domain, VipsImage *im );
int vips_check_coding_known( const char *domain, VipsImage *im );
int vips_check_coding_labq( const char *domain, VipsImage *im );
int vips_check_coding_rad( const char *domain, VipsImage *im );
int vips_check_coding_noneorlabq( const char *domain, VipsImage *im );
int vips_check_coding_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int vips_check_mono( const char *domain, VipsImage *im );
int vips_check_bands_1or3( const char *domain, VipsImage *in );
int vips_check_bands( const char *domain, VipsImage *im, int bands );
int vips_check_bands_1orn( const char *domain, VipsImage *im1, VipsImage *im2 );
int vips_check_bands_1orn_unary( const char *domain, VipsImage *im, int n );
int vips_check_bands_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int vips_check_bandno( const char *domain, VipsImage *im, int bandno );
int vips_check_int( const char *domain, VipsImage *im );
int vips_check_uint( const char *domain, VipsImage *im );
int vips_check_uintorf( const char *domain, VipsImage *im );
int vips_check_noncomplex( const char *domain, VipsImage *im );
int vips_check_complex( const char *domain, VipsImage *im );
int vips_check_format( const char *domain, VipsImage *im, VipsBandFormat fmt );
int vips_check_u8or16( const char *domain, VipsImage *im );
int vips_check_8or16( const char *domain, VipsImage *im );
int vips_check_u8or16orf( const char *domain, VipsImage *im );
int vips_check_format_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int vips_check_size_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int vips_check_vector( const char *domain, int n, VipsImage *im );
int vips_check_hist( const char *domain, VipsImage *im );
int vips_check_imask( const char *domain, INTMASK *mask );
int vips_check_dmask( const char *domain, DOUBLEMASK *mask );
int vips_check_dmask_1d( const char *domain, DOUBLEMASK *mask );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_ERROR_H*/
