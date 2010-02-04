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

int im_rwcheck( IMAGE *im );
int im_iocheck( IMAGE *in, IMAGE *out );
int im_incheck( IMAGE *im );
int im_outcheck( IMAGE *im );
int im_piocheck( IMAGE *in, IMAGE *out );
int im_pincheck( IMAGE *im );
int im_poutcheck( IMAGE *im );

int im_check_uncoded( const char *domain, IMAGE *im );
int im_check_coding_known( const char *domain, IMAGE *im );
int im_check_coding_same( const char *domain, IMAGE *im1, IMAGE *im2 );
int im_check_mono( const char *domain, IMAGE *im );
int im_check_bands_1or3( const char *domain, IMAGE *in );
int im_check_bands( const char *domain, IMAGE *im, int bands );
int im_check_bands_1orn( const char *domain, IMAGE *im1, IMAGE *im2 );
int im_check_bands_same( const char *domain, IMAGE *im1, IMAGE *im2 );
int im_check_int( const char *domain, IMAGE *im );
int im_check_uint( const char *domain, IMAGE *im );
int im_check_noncomplex( const char *domain, IMAGE *im );
int im_check_complex( const char *domain, IMAGE *im );
int im_check_format( const char *domain, IMAGE *im, VipsBandFmt fmt );
int im_check_u8or16( const char *domain, IMAGE *im );
int im_check_format_same( const char *domain, IMAGE *im1, IMAGE *im2 );
int im_check_size_same( const char *domain, IMAGE *im1, IMAGE *im2 );
int im_check_vector( const char *domain, int n, IMAGE *im );
int im_check_imask( const char *domain, INTMASK *mask );
int im_check_dmask( const char *domain, DOUBLEMASK *mask );

gboolean vips_bandfmt_isint( VipsBandFmt fmt );
gboolean vips_bandfmt_isuint( VipsBandFmt fmt );
gboolean vips_bandfmt_isfloat( VipsBandFmt fmt );
gboolean vips_bandfmt_iscomplex( VipsBandFmt fmt );

gboolean im_isfile( IMAGE *im );
gboolean im_ispartial( IMAGE *im );

gboolean im_isMSBfirst( IMAGE *im );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CHECK_H*/
