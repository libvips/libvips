/* load UltraHDR images with libuhdr
 *
 * 19/1/19
 * 	- from uhdrload.c
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_UHDR

#include "pforeign.h"

const char *vips__uhdr_suffs[] = {
	".jpg",
	NULL
};

#include <libuhdr/uhdr.h>

#define VIPS_TYPE_FOREIGN_LOAD_UHDR (vips_foreign_load_uhdr_get_type())
#define VIPS_FOREIGN_LOAD_UHDR(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdr))
#define VIPS_FOREIGN_LOAD_UHDR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdrClass))
#define VIPS_IS_FOREIGN_LOAD_UHDR(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_FOREIGN_LOAD_UHDR))
#define VIPS_IS_FOREIGN_LOAD_UHDR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_FOREIGN_LOAD_UHDR))
#define VIPS_FOREIGN_LOAD_UHDR_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdrClass))

typedef struct _VipsForeignLoadUhdr {
	VipsForeignLoad parent_object;

	/* Context for this image.
	 */
	struct uhdr_context *ctx;

	/* Set from subclasses.
	 */
	VipsSource *source;

} VipsForeignLoadUhdr;

void
vips__uhdr_error(struct uhdr_error *error)
{
	if (error->code)
		vips_error("uhdr", "%s (%d.%d)",
			error->message ? error->message : "(null)",
			error->code, error->subcode);
}

typedef struct _VipsForeignLoadUhdrClass {
	VipsForeignLoadClass parent_class;

} VipsForeignLoadUhdrClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadUhdr, vips_foreign_load_uhdr,
	VIPS_TYPE_FOREIGN_LOAD);

static void
vips_foreign_load_uhdr_dispose(GObject *gobject)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) gobject;


	G_OBJECT_CLASS(vips_foreign_load_uhdr_parent_class)->dispose(gobject);
}

static int
vips_foreign_load_uhdr_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;

#ifdef DEBUG
	printf("vips_foreign_load_uhdr_build:\n");
#endif /*DEBUG*/

	if (uhdr->source &&
		vips_source_rewind(uhdr->source))
		return -1;

	if (!uhdr->ctx) {
		struct uhdr_error error;

		uhdr->ctx = uhdr_context_alloc();
		/* uhdrsave is limited to a maximum image size of 16384x16384,
		 * so align the uhdrload defaults accordingly.
		 */
		uhdr_context_set_maximum_image_size_limit(uhdr->ctx,
			uhdr->unlimited ? USHRT_MAX : 0x4000);
#ifdef HAVE_UHDR_MAX_TOTAL_MEMORY
		if (!uhdr->unlimited)
			uhdr_context_get_security_limits(uhdr->ctx)
				->max_total_memory = 2UL * 1024 * 1024 * 1024;
#endif /* HAVE_UHDR_MAX_TOTAL_MEMORY */
#ifdef HAVE_UHDR_GET_DISABLED_SECURITY_LIMITS
		if (uhdr->unlimited)
			uhdr_context_set_security_limits(uhdr->ctx,
				uhdr_get_disabled_security_limits());
#endif /* HAVE_UHDR_GET_DISABLED_SECURITY_LIMITS */
		error = uhdr_context_read_from_reader(uhdr->ctx,
			uhdr->reader, uhdr, NULL);
		if (error.code) {
			vips__uhdr_error(&error);
			return -1;
		}
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_parent_class)
		->build(object);
}

static int
vips_foreign_load_uhdr_is_a(const char *buf, int len)
{
	if (len >= 12) {
		unsigned char *p = (unsigned char *) buf;
		guint32 chunk_len =
			VIPS_LSHIFT_INT(p[0], 24) |
			VIPS_LSHIFT_INT(p[1], 16) |
			VIPS_LSHIFT_INT(p[2], 8) |
			VIPS_LSHIFT_INT(p[3], 0);

		int i;

		/* chunk_len can be pretty big for eg. animated AVIF.
		 */
		if (chunk_len > 2048 ||
			chunk_len % 4 != 0)
			return 0;

		for (i = 0; i < VIPS_NUMBER(uhdr_magic); i++)
			if (strncmp(buf + 4, uhdr_magic[i], 8) == 0)
				return 1;
	}

	return 0;
}

static VipsForeignFlags
vips_foreign_load_uhdr_get_flags(VipsForeignLoad *load)
{
	return VIPS_FOREIGN_RANDOM;
}

static int
vips_foreign_load_uhdr_set_header(VipsForeignLoadUhdr *uhdr, VipsImage *out)
{
	VipsForeignLoad *load = (VipsForeignLoad *) uhdr;

	return 0;
}

static int
vips_foreign_load_uhdr_header(VipsForeignLoad *load)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(load);
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) load;

	vips_source_minimise(uhdr->source);

	return 0;
}

static void
vips_foreign_load_uhdr_minimise(VipsObject *object, VipsForeignLoadUhdr *uhdr)
{
	vips_source_minimise(uhdr->source);
}

static int
vips_foreign_load_uhdr_load(VipsForeignLoad *load)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) load;

	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(load), 3);

#ifdef DEBUG
	printf("vips_foreign_load_uhdr_load: loading image\n");
#endif /*DEBUG*/

	return 0;
}

static void
vips_foreign_load_uhdr_class_init(VipsForeignLoadUhdrClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_uhdr_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_base";
	object_class->description = _("load a UHDR image");
	object_class->build = vips_foreign_load_uhdr_build;

	load_class->get_flags = vips_foreign_load_uhdr_get_flags;
	load_class->header = vips_foreign_load_uhdr_header;
	load_class->load = vips_foreign_load_uhdr_load;

}

static void
vips_foreign_load_uhdr_init(VipsForeignLoadUhdr *uhdr)
{
	uhdr->n = 1;

}

typedef struct _VipsForeignLoadUhdrFile {
	VipsForeignLoadUhdr parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadUhdrFile;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrFileClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrFile, vips_foreign_load_uhdr_file,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_file_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrFile *file = (VipsForeignLoadUhdrFile *) object;

	if (file->filename &&
		!(uhdr->source = vips_source_new_from_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_file_parent_class)
		->build(object);
}

static int
vips_foreign_load_uhdr_file_is_a(const char *filename)
{
	char buf[12];

	if (vips__get_bytes(filename, (unsigned char *) buf, 12) != 12)
		return 0;

	return vips_foreign_load_uhdr_is_a(buf, 12);
}

static void
vips_foreign_load_uhdr_file_class_init(VipsForeignLoadUhdrFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload";
	object_class->build = vips_foreign_load_uhdr_file_build;

	foreign_class->suffs = vips__uhdr_suffs;

	load_class->is_a = vips_foreign_load_uhdr_file_is_a;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrFile, filename),
		NULL);
}

static void
vips_foreign_load_uhdr_file_init(VipsForeignLoadUhdrFile *file)
{
}

typedef struct _VipsForeignLoadUhdrBuffer {
	VipsForeignLoadUhdr parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadUhdrBuffer;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrBufferClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrBuffer, vips_foreign_load_uhdr_buffer,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_buffer_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrBuffer *buffer =
		(VipsForeignLoadUhdrBuffer *) object;

	if (buffer->buf &&
		!(uhdr->source = vips_source_new_from_memory(
			VIPS_AREA(buffer->buf)->data,
			VIPS_AREA(buffer->buf)->length)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_buffer_parent_class)
		->build(object);
}

static gboolean
vips_foreign_load_uhdr_buffer_is_a(const void *buf, size_t len)
{
	return vips_foreign_load_uhdr_is_a(buf, len);
}

static void
vips_foreign_load_uhdr_buffer_class_init(
	VipsForeignLoadUhdrBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_buffer";
	object_class->build = vips_foreign_load_uhdr_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_uhdr_buffer_is_a;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_uhdr_buffer_init(VipsForeignLoadUhdrBuffer *buffer)
{
}

typedef struct _VipsForeignLoadUhdrSource {
	VipsForeignLoadUhdr parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadUhdrSource;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrSourceClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrSource, vips_foreign_load_uhdr_source,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_source_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrSource *source =
		(VipsForeignLoadUhdrSource *) object;

	if (source->source) {
		uhdr->source = source->source;
		g_object_ref(uhdr->source);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_source_parent_class)
		->build(object);
}

static gboolean
vips_foreign_load_uhdr_source_is_a_source(VipsSource *source)
{
	const char *p;

	return (p = (const char *) vips_source_sniff(source, 12)) &&
		vips_foreign_load_uhdr_is_a(p, 12);
}

static void
vips_foreign_load_uhdr_source_class_init(
	VipsForeignLoadUhdrSourceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_source";
	object_class->build = vips_foreign_load_uhdr_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_uhdr_source_is_a_source;

	VIPS_ARG_OBJECT(class, "source", 1,
		_("Source"),
		_("Source to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrSource, source),
		VIPS_TYPE_SOURCE);
}

static void
vips_foreign_load_uhdr_source_init(VipsForeignLoadUhdrSource *source)
{
}

#endif /*HAVE_UHDR*/

/* The C API wrappers are defined in foreign.c.
 */
