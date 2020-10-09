/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_BISTEAM_H
#define HAVE_BISTEAM_H

#include <stdint.h>
#include <glib.h>


enum bistream_direction
{
	bistream_in,
	bistream_out
};

struct stream_chunk
{
	GString *data;
	uint32_t bistream_offset;
	uint32_t stream_offset;
	enum bistream_direction direction;
};

struct bistream
{
	GList *stream_sequence;
	GMutex mutex;

	struct stream
	{
		GList *stream_chunks;
		GMutex mutex;
	}streams[2];
};

uint32_t sizeof_stream_chunks(GList *stream_chunks);

struct bistream *bistream_new(void);
void bistream_free(struct bistream *bs);

void bistream_data_add(struct bistream *bs, enum bistream_direction, void *data, uint32_t size);
void bistream_debug(struct bistream *bs);

int32_t bistream_get_stream(struct bistream *bs, enum bistream_direction dir, uint32_t start, int32_t end, void **data);

void print_stream_chunk(struct stream_chunk *sc);
void print_stream_chunk2(struct stream_chunk *sc);

#endif
