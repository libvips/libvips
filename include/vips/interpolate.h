/* Various interpolators.
 *
 * J.Cupitt, 15/10/08
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

#ifndef IM_INTERPOLATE_H
#define IM_INTERPOLATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define TYPE_MODEL (model_get_type())
#define MODEL( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), TYPE_MODEL, Model ))
#define MODEL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), TYPE_MODEL, ModelClass))
#define IS_MODEL( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), TYPE_MODEL ))
#define IS_MODEL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), TYPE_MODEL ))
#define MODEL_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), TYPE_MODEL, ModelClass ))

struct _Model {
	iContainer parent;

	/* My instance vars.
	 */
};

typedef struct _ModelClass {
	iContainerClass parent_class;

} ModelClass;


#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_REGION_H*/

