/* defs for fits read/write
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

#ifndef VIPS_FITS_H
#define VIPS_FITS_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

extern const char *vips__fits_suffs[];

int vips__fits_isfits( const char *filename );
int vips__fits_read_header( const char *filename, VipsImage *out );
int vips__fits_read( const char *filename, VipsImage *out );

int vips__fits_write( VipsImage *in, const char *filename );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_FITS_H*/
