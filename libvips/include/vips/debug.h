/* Support for debug.c in iofuncs.
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

#ifndef IM_DEBUG_H
#define IM_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* All open image descriptors ... see im_init() and im_close().
 */
extern GSList *im__open_images;

/* Print one line for each descriptor, complete dump for one descriptor.
 */
void im__print_one( int n );
void im__print_all( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* IM_DEBUG_H */
