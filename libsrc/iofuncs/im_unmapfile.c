/* @(#) Function which unmaps a file memory mapped by mapfile()
 * @(#) The argument baseaddress should be the pointer returned by mapfile();
 * @(#) The function finds the size of the file from
 * @(#) 
 * @(#) int im_unmapfile(fd, baseaddress)
 * @(#) int fd;
 * @(#) char *baseaddress; 
 * @(#)
 * @(#) Returns 0 on success and -1 on error.
 * @(#)
 * Copyright: Nicos Dessipris
 * Wriiten on: 13/02/1990
 * Updated on:
 * 18/4/97 JC
 *	- ANSIfied
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <sys/types.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include <sys/stat.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_unmapfile( IMAGE *im )
{
	if( im__munmap( im->baseaddr, im->length ) ) 
		return( -1 );
	im->baseaddr = NULL;
	im->length = 0;

	return( 0 );
}
