/* check images for various properties
 *
 * J.Cupitt, 8/4/93
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

#ifndef IM_CHECK_H
#define IM_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_check_uncoded( const char *domain, VipsImage *im );
int im_check_coding_known( const char *domain, VipsImage *im );
int im_check_coding_labq( const char *domain, VipsImage *im );
int im_check_coding_rad( const char *domain, VipsImage *im );
int im_check_coding_noneorlabq( const char *domain, VipsImage *im );
int im_check_coding_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int im_check_mono( const char *domain, VipsImage *im );
int im_check_bands_1or3( const char *domain, VipsImage *in );
int im_check_bands( const char *domain, VipsImage *im, int bands );
int im_check_bands_1orn( const char *domain, VipsImage *im1, VipsImage *im2 );
int im_check_bands_1orn_unary( const char *domain, VipsImage *im, int n );
int im_check_bands_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int im_check_bandno( const char *domain, VipsImage *im, int bandno );
int im_check_int( const char *domain, VipsImage *im );
int im_check_uint( const char *domain, VipsImage *im );
int im_check_uintorf( const char *domain, VipsImage *im );
int im_check_noncomplex( const char *domain, VipsImage *im );
int im_check_complex( const char *domain, VipsImage *im );
int im_check_format( const char *domain, VipsImage *im, VipsBandFormat fmt );
int im_check_u8or16( const char *domain, VipsImage *im );
int im_check_8or16( const char *domain, VipsImage *im );
int im_check_u8or16orf( const char *domain, VipsImage *im );
int im_check_format_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int im_check_size_same( const char *domain, VipsImage *im1, VipsImage *im2 );
int im_check_vector( const char *domain, int n, VipsImage *im );
int im_check_hist( const char *domain, VipsImage *im );
int im_check_imask( const char *domain, INTMASK *mask );
int im_check_dmask( const char *domain, DOUBLEMASK *mask );

gboolean vips_bandfmt_isint( VipsBandFormat fmt );
gboolean vips_bandfmt_isuint( VipsBandFormat fmt );
gboolean vips_bandfmt_isfloat( VipsBandFormat fmt );
gboolean vips_bandfmt_iscomplex( VipsBandFormat fmt );

gboolean im_isfile( VipsImage *im );
gboolean im_ispartial( VipsImage *im );

gboolean im_isMSBfirst( VipsImage *im );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CHECK_H*/
