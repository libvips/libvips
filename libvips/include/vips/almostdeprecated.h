/* Old and broken stuff that we still enable by default
 *
 * 30/6/09
 * 	- from vips.h
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

#ifndef IM_ALMOSTDEPRECATED_H
#define IM_ALMOSTDEPRECATED_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Was public, now deprecated.
 */
typedef enum {
	IM_BBITS_BYTE = 8,
	IM_BBITS_SHORT = 16,
	IM_BBITS_INT = 32,
	IM_BBITS_FLOAT = 32,
	IM_BBITS_COMPLEX = 64,
	IM_BBITS_DOUBLE = 64,
	IM_BBITS_DPCOMPLEX = 128
} VipsBBits;

/* Used to define a region of interest for im_extract() etc. Too boring to be
 * public API, see im_extract_area() etc.
 */
typedef struct { 
	int xstart;
	int ystart;
	int xsize;
	int ysize;
	int chsel;      /* 1 2 3 or 0, for r g b or all respectively
			 *(channel select)	*/
} IMAGE_BOX;

/* Compatibility typedefs.
 */
typedef VipsDemandStyle im_demand_type;
typedef VipsProgress im_time_t;
typedef VipsImage IMAGE;

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_ALMOSTDEPRECATED_H*/
