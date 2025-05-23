/* memory utilities
 *
 * J.Cupitt, 8/4/93
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
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_MEMORY_H
#define VIPS_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_FREEF(F, S) \
	G_STMT_START \
	{ \
		if (S) { \
			(void) F((S)); \
			(S) = 0; \
		} \
	} \
	G_STMT_END

#define VIPS_FREE(S) VIPS_FREEF(g_free, (S));

#define VIPS_SETSTR(S, V) \
	G_STMT_START \
	{ \
		const char *sst = (V); \
		\
		if ((S) != sst) { \
			if (!(S) || !sst || strcmp((S), sst) != 0) { \
				VIPS_FREE(S); \
				if (sst) \
					(S) = g_strdup(sst); \
			} \
		} \
	} \
	G_STMT_END

#define VIPS_MALLOC(OBJ, S) \
	(vips_malloc(VIPS_OBJECT(OBJ), S))
#define VIPS_NEW(OBJ, T) \
	((T *) VIPS_MALLOC(OBJ, sizeof(T)))
#define VIPS_ARRAY(OBJ, N, T) \
	((T *) VIPS_MALLOC(OBJ, (N) * sizeof(T)))

#ifndef __GI_SCANNER__

G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsImage, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsObject, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsRegion, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsConnection, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsSource, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsSourceCustom, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsGInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsSourceGInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsTarget, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsTargetCustom, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsSbuf, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsInterpolate, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsOperation, g_object_unref)

// FIXME ... need more of these
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsArrayDouble, VipsArrayDouble_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsArrayImage, VipsArrayImage_unref)

#endif /* !__GI_SCANNER__ */

VIPS_API
void *vips_malloc(VipsObject *object, size_t size);
VIPS_API
char *vips_strdup(VipsObject *object, const char *str);

VIPS_API
void vips_tracked_free(void *s);
VIPS_API
void vips_tracked_aligned_free(void *s);
VIPS_API
void *vips_tracked_malloc(size_t size);
VIPS_API
void *vips_tracked_aligned_alloc(size_t size, size_t align);
VIPS_API
size_t vips_tracked_get_mem(void);
VIPS_API
size_t vips_tracked_get_mem_highwater(void);
VIPS_API
int vips_tracked_get_allocs(void);

VIPS_API
int vips_tracked_open(const char *pathname, int flags, int mode);
VIPS_API
int vips_tracked_close(int fd);
VIPS_API
int vips_tracked_get_files(void);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_MEMORY_H*/
