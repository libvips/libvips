/* Suppprted image formats.
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

#ifndef IM_FORMAT_H
#define IM_FORMAT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Image file properties. OR these together to get the result of
 * im_format_flags_fn(). 0 is default.
 */
typedef enum {
	IM_FORMAT_FLAG_NONE = 0,/* No flags set */
	IM_FORMAT_FLAG_PARTIAL = 1/* Lazy read OK (eg. tiled tiff) */
} im_format_flags;

/* Function protos for formats.
 */
typedef gboolean (*im_format_is_a_fn)( const char * );
typedef int (*im_format_header_fn)( const char *, IMAGE * );
typedef int (*im_format_load_fn)( const char *, IMAGE * );
typedef int (*im_format_save_fn)( IMAGE *, const char * );
typedef im_format_flags (*im_format_flags_fn)( const char * );

/* A VIPS image format. 
 */
typedef struct {
	const char *name;	/* Format name, same as mime */
	const char *name_user;	/* I18n'd name for users */
	int priority;		/* Keep formats sorted by this, default 0 */
	const char **suffs; 	/* Allowed suffixes */
	im_format_is_a_fn is_a;	/* Filename is in format */
	im_format_header_fn header;/* Load header only from filename */
	im_format_load_fn load;	/* Load image from filename */
	im_format_save_fn save;	/* Save image to filename */
	im_format_flags_fn flags;/* Get flags for filename */
} im_format;

/* Register/unregister formats.
 */
im_format *im_format_register( 
	const char *name, const char *name_user, const char **suffs,
	im_format_is_a_fn is_a, im_format_header_fn header,
	im_format_load_fn load, im_format_save_fn save,
	im_format_flags_fn flags );
void im_format_set_priority( im_format *format, int priority );
void im_format_unregister( im_format *format );

/* Map over and find formats.
 */
void *im_format_map( VSListMap2Fn fn, void *a, void *b );
im_format *im_format_for_file( const char *filename );
im_format *im_format_for_name( const char *filename );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_FORMAT_H*/
