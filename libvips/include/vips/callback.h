/* Various callbacks.
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_CALLBACK_H
#define IM_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/


int im_add_close_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );
int im_add_preclose_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );
int im_add_postclose_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );

int im_add_written_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );

int im_add_evalstart_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );
int im_add_eval_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );
int im_add_evalend_callback( IMAGE *im, im_callback_fn fn, void *a, void *b );

int im_add_invalidate_callback( IMAGE *im, 
	im_callback_fn fn, void *a, void *b );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*!IM_CALLBACK_H*/
