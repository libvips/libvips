/* Write raw image data to file. Usefull when defining new formats...
 *
 * Jesper Friis
 *
 * 10/06/08 JF
 *	- initial code based on im_vips2ppm()
 *
 * 04/07/08 JF
 *      - replaced FILE with plain file handlers for reducing
 *        confusion about binary vs. non-binary file modes.
 * 4/2/10
 * 	- gtkdoc
 */


/*
    This file is part of the QED plugin to VIPS.
    
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <glib.h>
#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/



/* What we track during a write
 */
typedef struct {
  IMAGE *in;
  im_threadgroup_t *tg;
  int fd;
} Write;



static void
write_destroy( Write *write )
{
  IM_FREEF( im_threadgroup_free, write->tg );
  im_free( write );
}


static Write *
write_new( IMAGE *in, int fd )
{
  Write *write;

  if( !(write = IM_NEW( NULL, Write )) )
    return( NULL );

  write->in = in;
  write->tg = im_threadgroup_create( write->in );
  write->fd = fd;
  
  if( !write->tg || !write->fd ) {
    write_destroy( write );
    return( NULL );
  }
  
  return( write );
}


static int
write_block( REGION *region, Rect *area, void *a, void *b )
{
  Write *write = (Write *) a;
  int i;
  
  for( i = 0; i < area->height; i++ ) {
    PEL *p = (PEL *) IM_REGION_ADDR( region, area->left, area->top + i );
    if( im__write( write->fd, p, IM_IMAGE_SIZEOF_PEL(write->in)*area->width ) )
      return( -1 );
  }
  
  return( 0 );
}


/**
 * im_vips2raw:
 * @in: image to save 
 * @fd: file descriptor to write to
 *
 * Writes the pixels in @in to the file descriptor. It's handy for writing
 * writers for other formats.
 *
 * See also: #VipsFormat, im_raw2vips().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2raw( IMAGE *in, int fd )
{
  Write *write;
      
  if( im_pincheck( in ) || !(write = write_new( in, fd )) )
    return( -1 );

  if( im_wbuffer( write->tg, write_block, write, NULL ) ) {
    write_destroy( write );
    return( -1 );
  }  

  write_destroy( write );
  return( 0 );
}

