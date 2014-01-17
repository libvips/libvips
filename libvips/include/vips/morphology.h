/* morphology.h
 *
 * 20/9/09
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_MORPHOLOGY_H
#define VIPS_MORPHOLOGY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips_countlines( VipsImage *in, double *nolines, 
	VipsDirection direction, ... )
	__attribute__((sentinel));

int vips_rank( VipsImage *in, VipsImage **out, 
	int width, int height, int index, ... )
	__attribute__((sentinel));
int vips_median( VipsImage *in, VipsImage **out, int size, ... )
	__attribute__((sentinel));




int im_zerox( VipsImage *in, VipsImage *out, int sign );
int im_label_regions( VipsImage *test, VipsImage *mask, int *segments );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_MORPHOLOGY_H*/
