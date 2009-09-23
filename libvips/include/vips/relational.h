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

int im_equal( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_notequal( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_less( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_lesseq( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_more( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_moreeq( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_equal_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_notequal_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_less_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_lesseq_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_more_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_moreeq_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_equalconst( IMAGE *in, IMAGE *out, double c );
int im_notequalconst( IMAGE *in, IMAGE *out, double c );
int im_lessconst( IMAGE *in, IMAGE *out, double c );
int im_lesseqconst( IMAGE *in, IMAGE *out, double c );
int im_moreconst( IMAGE *in, IMAGE *out, double c );
int im_moreeqconst( IMAGE *in, IMAGE *out, double c );

int im_ifthenelse( IMAGE *c, IMAGE *a, IMAGE *b, IMAGE *out );
int im_blend( IMAGE *c, IMAGE *a, IMAGE *b, IMAGE *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_RELATIONAL_H*/
