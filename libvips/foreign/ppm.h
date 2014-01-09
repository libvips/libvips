/* common defs for ppm read/write
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_PPM_H
#define VIPS_PPM_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips__ppm_header( const char *name, VipsImage *out );
int vips__ppm_load( const char *name, VipsImage *out );
int vips__ppm_isppm( const char *filename );
VipsForeignFlags vips__ppm_flags( const char *filename );
extern const char *vips__ppm_suffs[];

int vips__ppm_save( VipsImage *in, const char *filename, 
	gboolean ascii ); 

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PPM_H*/
