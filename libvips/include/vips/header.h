/* boolean.h
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_HEADER_H
#define IM_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_header_int( IMAGE *im, const char *field, int *out );
int im_header_double( IMAGE *im, const char *field, double *out );
int im_header_string( IMAGE *im, const char *field, char **out );
GType im_header_get_typeof( IMAGE *im, const char *field );
int im_header_get( IMAGE *im, const char *field, GValue *value_copy );

typedef void *(*im_header_map_fn)( IMAGE *, const char *, GValue *, void * );
void *im_header_map( IMAGE *im, im_header_map_fn fn, void *a );

int im_histlin( IMAGE *image, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
int im_updatehist( IMAGE *out, const char *name, int argc, char *argv[] );
const char *im_history_get( IMAGE *im );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_HEADER_H*/
