
#ifndef __vips_MARSHAL_H__
#define __vips_MARSHAL_H__

#include	<glib-object.h>

G_BEGIN_DECLS

/* INT:VOID (vipsmarshal.list:25) */
extern void vips_INT__VOID (GClosure     *closure,
                            GValue       *return_value,
                            guint         n_param_values,
                            const GValue *param_values,
                            gpointer      invocation_hint,
                            gpointer      marshal_data);

G_END_DECLS

#endif /* __vips_MARSHAL_H__ */

