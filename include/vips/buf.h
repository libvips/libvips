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

#ifndef IM_BUF_H
#define IM_BUF_H

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
} im_buf_t;

/* Static init of one of these.
 */
#define IM_BUF_STATIC( TEXT, MAX ) \
        { &TEXT[0], MAX, 0, FALSE, 0, FALSE }

void im_buf_rewind( im_buf_t *buf );
void im_buf_destroy( im_buf_t *buf );
void im_buf_init( im_buf_t *buf ); 
void im_buf_set_static( im_buf_t *buf, char *base, int mx );
void im_buf_set_dynamic( im_buf_t *buf, int mx );
void im_buf_init_static( im_buf_t *buf, char *base, int mx );
void im_buf_init_dynamic( im_buf_t *buf, int mx );
gboolean im_buf_appendns( im_buf_t *buf, const char *str, int sz );
gboolean im_buf_appends( im_buf_t *buf, const char *str );
gboolean im_buf_appendline( im_buf_t *buf, const char *str );
gboolean im_buf_appendf( im_buf_t *buf, const char *fmt, ... )
	__attribute__((format(printf, 2, 3)));
gboolean im_buf_vappendf( im_buf_t *buf, const char *fmt, va_list ap );
gboolean im_buf_appendc( im_buf_t *buf, char ch );
gboolean im_buf_appendg( im_buf_t *buf, double g );
gboolean im_buf_appendsc( im_buf_t *buf, const char *str );
gboolean im_buf_removec( im_buf_t *buf, char ch );
gboolean im_buf_change( im_buf_t *buf, const char *old, const char * );
gboolean im_buf_isempty( im_buf_t *buf );
gboolean im_buf_isfull( im_buf_t *buf );
const char *im_buf_all( im_buf_t *buf );
gboolean im_buf_appendd( im_buf_t *buf, int d );
int im_buf_len( im_buf_t *buf );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_BUF_H*/


