/* relational.h
 *
 * 23/9/09
 * 	- from proto.h
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

#ifndef IM_RELATIONAL_H
#define IM_RELATIONAL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_equal( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_notequal( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_less( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_lesseq( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_more( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_moreeq( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_equal_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_notequal_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_less_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_lesseq_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_more_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_moreeq_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_equalconst( VipsImage *in, VipsImage *out, double c );
int im_notequalconst( VipsImage *in, VipsImage *out, double c );
int im_lessconst( VipsImage *in, VipsImage *out, double c );
int im_lesseqconst( VipsImage *in, VipsImage *out, double c );
int im_moreconst( VipsImage *in, VipsImage *out, double c );
int im_moreeqconst( VipsImage *in, VipsImage *out, double c );

int im_ifthenelse( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );
int im_blend( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_RELATIONAL_H*/
