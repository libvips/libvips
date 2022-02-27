/* i18n stuff for vips. Deprecated in favour of glib/gi18n.h.
 */

#ifndef VIPS_INTL_H
#define VIPS_INTL_H

#ifdef ENABLE_NLS

#include <glib/gi18n.h>

#else /*!ENABLE_NLS*/

#define _(String) (String)
#define N_(String) (String)

#endif /* ENABLE_NLS */

#endif /* VIPS_INTL_H */
