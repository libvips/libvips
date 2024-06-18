/* A byte source/sink .. it can be a pipe, file descriptor, memory area,
 * socket, node.js stream, etc.
 *
 * J.Cupitt, 19/6/14
 *
 * 26/11/20
 * 	- use _setmode() on win to force binary write for previously opened
 * 	  descriptors
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vips/vips.h>

#ifdef G_OS_WIN32
#include <io.h>
#endif /*G_OS_WIN32*/

#include <vips/debug.h>
#include <vips/internal.h>

/* libtiff needs to be able to seek and read back output files, unfortunately,
 * so we must open read-write.
 */
#define MODE_READWRITE CLOEXEC(BINARYIZE(O_RDWR | O_CREAT | O_TRUNC))

G_DEFINE_TYPE(VipsTarget, vips_target, VIPS_TYPE_CONNECTION);

static void
vips_target_finalize(GObject *gobject)
{
	VipsTarget *target = VIPS_TARGET(gobject);

	VIPS_DEBUG_MSG("vips_target_finalize:\n");

	if (target->memory_buffer) {
		g_string_free(target->memory_buffer, TRUE);
		target->memory_buffer = NULL;
	}

	if (target->blob) {
		vips_area_unref(VIPS_AREA(target->blob));
		target->blob = NULL;
	}

	if (target->delete_on_close &&
		target->delete_on_close_filename)
		g_unlink(target->delete_on_close_filename);

	VIPS_FREE(target->delete_on_close_filename);

	G_OBJECT_CLASS(vips_target_parent_class)->finalize(gobject);
}

static int
vips_target_build(VipsObject *object)
{
	VipsConnection *connection = VIPS_CONNECTION(object);
	VipsTarget *target = VIPS_TARGET(object);

	VIPS_DEBUG_MSG("vips_target_build: %p\n", connection);

	if (VIPS_OBJECT_CLASS(vips_target_parent_class)->build(object))
		return -1;

	if (vips_object_argument_isset(object, "filename") &&
		vips_object_argument_isset(object, "descriptor")) {
		vips_error(vips_connection_nick(connection),
			"%s", _("don't set 'filename' and 'descriptor'"));
		return -1;
	}

	if (connection->filename) {
		const char *filename = connection->filename;

		int fd;

		/* 0644 is rw user, r group and other.
		 */
		if ((fd = vips_tracked_open(filename,
				 MODE_READWRITE, 0644)) == -1) {
			vips_error_system(errno,
				vips_connection_nick(connection),
				"%s", _("unable to open for write"));
			return -1;
		}

		connection->tracked_descriptor = fd;
		connection->descriptor = fd;
	}
	else if (vips_object_argument_isset(object, "descriptor")) {
		connection->descriptor = dup(connection->descriptor);
		connection->close_descriptor = connection->descriptor;

#ifdef G_OS_WIN32
		/* Windows will create eg. stdin and stdout in text mode.
		 * We always write in binary mode.
		 */
		_setmode(connection->descriptor, _O_BINARY);
#endif /*G_OS_WIN32*/
	}
	else if (target->memory)
		target->memory_buffer =
			g_string_sized_new(VIPS_TARGET_BUFFER_SIZE);

	return 0;
}

static gint64
vips_target_write_real(VipsTarget *target, const void *data, size_t length)
{
	VipsConnection *connection = VIPS_CONNECTION(target);

	gint64 result;

	VIPS_DEBUG_MSG("vips_target_write_real: %zd bytes\n", length);

	if (target->memory_buffer) {
		VIPS_DEBUG_MSG("vips_target_write_real: to position %zd\n",
			target->position);

		g_string_overwrite_len(target->memory_buffer, target->position,
			data, length);
		target->position += length;
		result = length;
	}
	else
		result = write(connection->descriptor, data, length);

	return result;
}

static gint64
vips_target_seek_real(VipsTarget *target, gint64 offset, int whence)
{
	VipsConnection *connection = VIPS_CONNECTION(target);
	const char *nick = vips_connection_nick(connection);

	gint64 new_position;

	VIPS_DEBUG_MSG(
		"vips_target_seek_real: offset = %" G_GINT64_FORMAT
		", whence = %d\n",
		offset, whence);

	if (target->memory_buffer) {
		switch (whence) {
		case SEEK_SET:
			new_position = offset;
			break;

		case SEEK_CUR:
			new_position = target->position + offset;
			break;

		case SEEK_END:
			new_position = target->memory_buffer->len + offset;
			break;

		default:
			vips_error(nick, "%s", _("bad 'whence'"));
			return -1;
		}

		if (new_position > target->memory_buffer->len)
			g_string_set_size(target->memory_buffer,
				new_position);

		target->position = new_position;
	}
	else
		/* We need to use the vips__seek() wrapper so we can seek long
		 * files on Windows.
		 */
		new_position = vips__seek_no_error(connection->descriptor,
			offset, whence);

	return new_position;
}

static gint64
vips_target_read_real(VipsTarget *target, void *data, size_t length)
{
	gint64 bytes_read;

	VIPS_DEBUG_MSG("vips_target_read_real: %zd bytes\n", length);

	if (target->memory_buffer) {
		bytes_read = VIPS_MIN(length,
			target->memory_buffer->len - target->position);

		VIPS_DEBUG_MSG("    %zd bytes from memory\n", bytes_read);
		memcpy(data,
			target->memory_buffer->str +
				target->position,
			bytes_read);
		target->position += bytes_read;
	}
	else {
		VipsConnection *connection = VIPS_CONNECTION(target);
		int fd = connection->descriptor;

		do {
			bytes_read = read(fd, data, length);
		} while (bytes_read < 0 && errno == EINTR);
	}

	VIPS_DEBUG_MSG("  read %zd bytes\n", bytes_read);

	return bytes_read;
}

static int
vips_target_end_real(VipsTarget *target)
{
	VIPS_DEBUG_MSG("vips_target_finish_real:\n");

	return 0;
}

static void
vips_target_finish_real(VipsTarget *target)
{
	VIPS_DEBUG_MSG("vips_target_finish_real:\n");
}

static void
vips_target_class_init(VipsTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS(class);

	gobject_class->finalize = vips_target_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "target";
	object_class->description = _("Target");

	object_class->build = vips_target_build;

	class->write = vips_target_write_real;
	class->read = vips_target_read_real;
	class->seek = vips_target_seek_real;
	class->end = vips_target_end_real;
	class->finish = vips_target_finish_real;

	VIPS_ARG_BOOL(class, "memory", 3,
		_("Memory"),
		_("File descriptor should output to memory"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsTarget, memory),
		FALSE);

	/* SET_ALWAYS means that blob is set by C and the obj system is not
	 * involved in creation or destruction. It can be read at any time.
	 */
	VIPS_ARG_BOXED(class, "blob", 4,
		_("Blob"),
		_("Blob to save to"),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET(VipsTarget, blob),
		VIPS_TYPE_BLOB);
}

static void
vips_target_init(VipsTarget *target)
{
	target->blob = vips_blob_new(NULL, NULL, 0);
	target->write_point = 0;
}

/**
 * vips_target_new_to_descriptor:
 * @descriptor: write to this file descriptor
 *
 * Create a target attached to a file descriptor.
 * @descriptor is kept open until the target is finalized.
 *
 * See also: vips_target_new_to_file().
 *
 * Returns: a new target.
 */
VipsTarget *
vips_target_new_to_descriptor(int descriptor)
{
	VipsTarget *target;

	VIPS_DEBUG_MSG("vips_target_new_to_descriptor: %d\n",
		descriptor);

	target = VIPS_TARGET(g_object_new(VIPS_TYPE_TARGET,
		"descriptor", descriptor,
		NULL));

	if (vips_object_build(VIPS_OBJECT(target))) {
		VIPS_UNREF(target);
		return NULL;
	}

	return target;
}

/**
 * vips_target_new_to_file:
 * @filename: write to this file
 *
 * Create a target attached to a file.
 *
 * Returns: a new target.
 */
VipsTarget *
vips_target_new_to_file(const char *filename)
{
	VipsTarget *target;

	VIPS_DEBUG_MSG("vips_target_new_to_file: %s\n",
		filename);

	target = VIPS_TARGET(g_object_new(VIPS_TYPE_TARGET,
		"filename", filename,
		NULL));

	if (vips_object_build(VIPS_OBJECT(target))) {
		VIPS_UNREF(target);
		return NULL;
	}

	return target;
}

/**
 * vips_target_new_to_memory:
 *
 * Create a target which will write to a memory area. Read from @blob to get
 * memory.
 *
 * See also: vips_target_new_to_file().
 *
 * Returns: a new #VipsConnection
 */
VipsTarget *
vips_target_new_to_memory(void)
{
	VipsTarget *target;

	VIPS_DEBUG_MSG("vips_target_new_to_memory:\n");

	target = VIPS_TARGET(g_object_new(VIPS_TYPE_TARGET,
		"memory", TRUE,
		NULL));

	if (vips_object_build(VIPS_OBJECT(target))) {
		VIPS_UNREF(target);
		return NULL;
	}

	return target;
}

/**
 * vips_target_new_temp:
 * @based_on: base the temporary target on this target
 *
 * Create a temporary target -- either a temporary file on disc, or an area in
 * memory, depending on what sort of target @based_on is.
 *
 * See also: vips_target_new_to_file().
 *
 * Returns: a new target.
 */
VipsTarget *
vips_target_new_temp(VipsTarget *based_on)
{
	VipsTarget *target;

	VIPS_DEBUG_MSG("vips_target_new_temp: %p\n", based_on);

	if (vips_connection_filename(VIPS_CONNECTION(based_on))) {
		int descriptor;
		char *filename;

		if (!(filename = vips__temp_name("%s.target")))
			return NULL;
		if ((descriptor =
					vips__open_image_write(filename, TRUE)) < 0) {
			g_free(filename);
			return NULL;
		}
		if (!(target = vips_target_new_to_descriptor(descriptor))) {
			g_free(filename);
			vips_tracked_close(descriptor);
			return NULL;
		}
		vips_tracked_close(descriptor);
		target->delete_on_close = TRUE;
		target->delete_on_close_filename = filename;
	}
	else
		target = vips_target_new_to_memory();

	return target;
}

static int
vips_target_write_unbuffered(VipsTarget *target,
	const void *data, size_t length)
{
	VipsTargetClass *class = VIPS_TARGET_GET_CLASS(target);

	VIPS_DEBUG_MSG("vips_target_write_unbuffered:\n");

	if (target->ended)
		return 0;

	while (length > 0) {
		// write() uses int not size_t on windows, so we need to chunk
		// ... max 1gb, why not
		int chunk_size = VIPS_MIN(1024 * 1024 * 1024, length);
		gint64 bytes_written = class->write(target, data, chunk_size);

		/* n == 0 isn't strictly an error, but we treat it as
		 * one to make sure we don't get stuck in this loop.
		 */
		if (bytes_written <= 0) {
			vips_error_system(errno,
				vips_connection_nick(
					VIPS_CONNECTION(target)),
				"%s", _("write error"));
			return -1;
		}

		length -= bytes_written;
		data = (char *) data + bytes_written;
	}

	return 0;
}

static int
vips_target_flush(VipsTarget *target)
{
	g_assert(target->write_point >= 0);
	g_assert(target->write_point <= VIPS_TARGET_BUFFER_SIZE);

	VIPS_DEBUG_MSG("vips_target_flush:\n");

	if (target->write_point > 0) {
		if (vips_target_write_unbuffered(target,
				target->output_buffer, target->write_point))
			return -1;
		target->write_point = 0;
	}

	return 0;
}

/**
 * vips_target_write:
 * @target: target to operate on
 * @buffer: bytes to write
 * @length: length of @buffer in bytes
 *
 * Write @length bytes from @buffer to the output.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_target_write(VipsTarget *target, const void *buffer, size_t length)
{
	VIPS_DEBUG_MSG("vips_target_write: %zd bytes\n", length);

	if (length > VIPS_TARGET_BUFFER_SIZE - target->write_point &&
		vips_target_flush(target))
		return -1;

	if (length > VIPS_TARGET_BUFFER_SIZE - target->write_point) {
		/* Still too large? Do an unbuffered write.
		 */
		if (vips_target_write_unbuffered(target, buffer, length))
			return -1;
	}
	else {
		memcpy(target->output_buffer + target->write_point,
			buffer, length);
		target->write_point += length;
	}

	return 0;
}

/**
 * vips_target_read:
 * @target: target to operate on
 * @buffer: store bytes here
 * @length: length of @buffer in bytes
 *
 * Read up to @length bytes from @target and store the bytes in @buffer.
 * Return the number of bytes actually read. If all bytes have been read from
 * the file, return 0.
 *
 * Arguments exactly as read(2).
 *
 * Reading from a target sounds weird, but libtiff needs this for
 * multi-page writes. This method will fail for targets like pipes.
 *
 * Returns: the number of bytes read, 0 on end of file, -1 on error.
 */
gint64
vips_target_read(VipsTarget *target, void *buffer, size_t length)
{
	VipsTargetClass *class = VIPS_TARGET_GET_CLASS(target);

	VIPS_DEBUG_MSG("vips_target_read: %zd bytes\n", length);

	if (vips_target_flush(target))
		return -1;

	return class->read(target, buffer, length);
}

/**
 * vips_target_seek:
 * @target: target to operate on
 * @position: position to seek to
 * @whence: seek relative to beginning, offset, or end
 *
 * Seek the target. This behaves exactly as lseek(2).
 *
 * Seeking a target sounds weird, but libtiff needs this. This method will
 * fail for targets like pipes.
 *
 * Returns: the new seek position, -1 on error.
 */
gint64
vips_target_seek(VipsTarget *target, gint64 position, int whence)
{
	VipsTargetClass *class = VIPS_TARGET_GET_CLASS(target);

	gint64 new_position;

	VIPS_DEBUG_MSG("vips_target_seek: pos = %" G_GINT64_FORMAT
		", whence = %d\n",
		position, whence);

	if (vips_target_flush(target))
		return -1;

	new_position = class->seek(target, position, whence);

	VIPS_DEBUG_MSG("vips_target_seek: new_position = %" G_GINT64_FORMAT "\n",
		new_position);

	return new_position;
}

/**
 * vips_target_end:
 * @target: target to operate on
 * @buffer: bytes to write
 * @length: length of @buffer in bytes
 *
 * Call this at the end of write to make the target do any cleaning up. You
 * can call it many times.
 *
 * After a target has been ended, further writes will do nothing.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_target_end(VipsTarget *target)
{
	VipsTargetClass *class = VIPS_TARGET_GET_CLASS(target);

	VIPS_DEBUG_MSG("vips_target_end:\n");

	if (target->ended)
		return 0;

	if (vips_target_flush(target))
		return -1;

	/* Move the target buffer into the blob so it can be read out.
	 */
	if (target->memory_buffer) {
		const char *data;
		size_t length;

		length = target->memory_buffer->len;
		data = g_string_free(target->memory_buffer, FALSE);
		target->memory_buffer = NULL;
		vips_blob_set(target->blob,
			(VipsCallbackFn) vips_area_free_cb, data, length);
	}
	else {
		if (class->end(target))
			return -1;
	}

	target->ended = TRUE;

	return 0;
}

/**
 * vips_target_finish:
 * @target: target to operate on
 * @buffer: bytes to write
 * @length: length of @buffer in bytes
 *
 * Deprecated in favour of vips_target_end().
 */
void
vips_target_finish(VipsTarget *target)
{
	(void) vips_target_end(target);
}

/**
 * vips_target_steal:
 * @target: target to operate on
 * @length: return number of bytes of data
 *
 * Memory targets only (see vips_target_new_to_memory()). Steal all data
 * written to the target so far, and call vips_target_end().
 *
 * You must free the returned pointer with g_free().
 *
 * The data is NOT automatically null-terminated. vips_target_putc() a '\0'
 * before calling this to get a null-terminated string.
 *
 * You can't call this after vips_target_end(), since that moves the data to a
 * blob, and we can't steal from that in case the pointer has been be shared.
 *
 * You can't call this function more than once.
 *
 * Returns: (array length=length) (element-type guint8) (transfer full): the
 * data
 */
unsigned char *
vips_target_steal(VipsTarget *target, size_t *length)
{
	const char *data;

	(void) vips_target_flush(target);

	data = NULL;

	if (target->memory_buffer) {
		if (length)
			*length = target->memory_buffer->len;
		data = g_string_free(target->memory_buffer, FALSE);
		target->memory_buffer = NULL;

		/* We must have a valid byte array, or end will fail.
		 */
		target->memory_buffer = g_string_sized_new(0);
	}

	if (vips_target_end(target))
		return NULL;

	return (unsigned char *) data;
}

/**
 * vips_target_steal_text:
 * @target: target to operate on
 *
 * As vips_target_steal_text(), but return a null-terminated string.
 *
 * Returns: (transfer full): target contents as a null-terminated string.
 */
char *
vips_target_steal_text(VipsTarget *target)
{
	vips_target_putc(target, '\0');

	return (char *) vips_target_steal(target, NULL);
}

/**
 * vips_target_putc:
 * @target: target to operate on
 * @ch: character to write
 *
 * Write a single character @ch to @target. See the macro VIPS_TARGET_PUTC()
 * for a faster way to do this.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_target_putc(VipsTarget *target, int ch)
{
	VIPS_DEBUG_MSG("vips_target_putc: %d\n", ch);

	if (target->write_point >= VIPS_TARGET_BUFFER_SIZE &&
		vips_target_flush(target))
		return -1;

	target->output_buffer[target->write_point++] = ch;

	return 0;
}

/**
 * vips_target_writes:
 * @target: target to operate on
 * @str: string to write
 *
 * Write a null-terminated string to @target.
 *
 * Returns: 0 on success, and -1 on error.
 */
int
vips_target_writes(VipsTarget *target, const char *str)
{
	return vips_target_write(target,
		(unsigned char *) str, strlen(str));
}

/**
 * vips_target_writef:
 * @target: target to operate on
 * @fmt: <function>printf()</function>-style format string
 * @...: arguments to format string
 *
 * Format the string and write to @target.
 *
 * Returns: 0 on success, and -1 on error.
 */
int
vips_target_writef(VipsTarget *target, const char *fmt, ...)
{
	va_list ap;
	char *line;
	int result;

	va_start(ap, fmt);
	line = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	result = vips_target_writes(target, line);

	g_free(line);

	return result;
}

/**
 * vips_target_write_amp:
 * @target: target to operate on
 * @str: string to write
 *
 * Write @str to @target, but escape stuff that xml hates in text. Our
 * argument string is utf-8.
 *
 * XML rules:
 *
 * - We must escape &<>
 * - Don't escape \n, \t, \r
 * - Do escape the other ASCII codes.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_target_write_amp(VipsTarget *target, const char *str)
{
	const char *p;

	for (p = str; *p; p++)
		if (*p < 32 &&
			*p != '\n' &&
			*p != '\t' &&
			*p != '\r') {
			/* You'd think we could output "&#x02%x;", but xml
			 * 1.0 parsers barf on that. xml 1.1 allows this, but
			 * there are almost no parsers.
			 *
			 * U+2400 onwards are unicode glyphs for the ASCII
			 * control characters, so we can use them -- thanks
			 * electroly.
			 */
			if (vips_target_writef(target,
					"&#x%04x;", 0x2400 + *p))
				return -1;
		}
		else if (*p == '<') {
			if (vips_target_writes(target, "&lt;"))
				return -1;
		}
		else if (*p == '>') {
			if (vips_target_writes(target, "&gt;"))
				return -1;
		}
		else if (*p == '&') {
			if (vips_target_writes(target, "&amp;"))
				return -1;
		}
		else {
			if (VIPS_TARGET_PUTC(target, *p))
				return -1;
		}

	return 0;
}
