/* A static string buffer, with overflow protection.
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

#ifndef IM_VBUF_H
#define IM_VBUF_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* A string in the process of being written to ... multiple calls to 
 * buf_append add to it, on overflow append "..." and block further writes.
 */
typedef struct {
        char *base;             /* String base */
        int mx;                 /* Maximum length */
        int i;                  /* Current write point */
        gboolean full;          /* String has filled, block writes */
        int lasti;              /* For read-recent */
        gboolean dynamic;       /* We own the string with malloc() */
} VBuf;

/* Static init of one of these.
 */
#define IM_BUF_STATIC( TEXT, MAX ) \
        { &TEXT[0], MAX, 0, FALSE, 0, FALSE }

void im_buf_rewind( VBuf *buf );
void im_buf_destroy( VBuf *buf );
void im_buf_init( VBuf *buf ); 
void im_buf_set_static( VBuf *buf, char *base, int mx );
void im_buf_set_dynamic( VBuf *buf, int mx );
void im_buf_init_static( VBuf *buf, char *base, int mx );
void im_buf_init_dynamic( VBuf *buf, int mx );
gboolean im_buf_appendns( VBuf *buf, const char *str, int sz );
gboolean im_buf_appends( VBuf *buf, const char *str );
gboolean im_buf_appendline( VBuf *buf, const char *str );
gboolean im_buf_appendf( VBuf *buf, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
gboolean im_buf_vappendf( VBuf *buf, const char *fmt, va_list ap );
gboolean im_buf_appendc( VBuf *buf, char ch );
gboolean im_buf_appendg( VBuf *buf, double g );
gboolean im_buf_appendsc( VBuf *buf, const char *str );
gboolean im_buf_removec( VBuf *buf, char ch );
gboolean im_buf_change( VBuf *buf, const char *old, const char * );
gboolean im_buf_isempty( VBuf *buf );
gboolean im_buf_isfull( VBuf *buf );
const char *im_buf_all( VBuf *buf );
gboolean im_buf_appendd( VBuf *buf, int d );
int im_buf_len( VBuf *buf );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_VBUF_H*/


