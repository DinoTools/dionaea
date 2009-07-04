/********************************************************************************
 *                               Dionaea
 *                           - catches bugs -
 *
 *
 *
 * Copyright (C) 2009  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@gmail.com  
 *
 *******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "log.h"

#define D_LOG_DOMAIN "bistream"

#include "bistream.h"

struct bistream *bistream_new()
{
	struct bistream *bs = g_malloc0(sizeof(struct bistream));
	enum bistream_direction it;
	for ( it = bistream_in; it <= bistream_out; it++ )
	{
		bs->streams[it].mutex = g_mutex_new();
		bs->streams[it].stream_chunks = NULL;
	}
	bs->stream_sequence = NULL;
	bs->mutex = g_mutex_new();
	return bs;
}

void bistream_free(struct bistream *bs)
{
	enum bistream_direction dir;
	for ( dir = bistream_in; dir <= bistream_out; dir++ )
	{
		g_mutex_free(bs->streams[dir].mutex);
		g_list_free(bs->streams[dir].stream_chunks);
	}
	
	GList *it;

	while ( (it = g_list_first(bs->stream_sequence)) != NULL)
	{
		struct stream_chunk *sc = it->data;
		g_string_free(sc->data, TRUE);
		g_free(sc);
		bs->stream_sequence = g_list_delete_link(bs->stream_sequence, it);
	}

	g_mutex_free(bs->mutex);
	g_free(bs);
}

struct stream_chunk *stream_chunk_new(void *data, uint32_t size, enum bistream_direction dir)
{
	struct stream_chunk *sc = g_malloc0(sizeof(struct stream_chunk));
	sc->data = g_string_new_len(data, size);
	sc->direction = dir;
	return sc;
}

void bistream_data_add(struct bistream *bs, enum bistream_direction dir, void *data, uint32_t size)
{
	g_debug("%s bs %p dir %i data %p size %i\n",__PRETTY_FUNCTION__, bs, dir, data, size);
	GList *lastbistream = g_list_last(bs->stream_sequence);
	GList *laststream = g_list_last(bs->streams[dir].stream_chunks);

	struct stream_chunk *lastbistreamsc = NULL;
	struct stream_chunk *laststreamsc = NULL;

	if (lastbistream != NULL)
		lastbistreamsc = lastbistream->data;

	if (laststream != NULL)
		laststreamsc = laststream->data;

	g_mutex_lock(bs->mutex);
	g_mutex_lock(bs->streams[dir].mutex);

	if (lastbistreamsc == laststreamsc && lastbistreamsc == NULL)
	{
		struct stream_chunk *sc = stream_chunk_new(data, size, dir);
		sc->bistream_offset = 0;
		sc->stream_offset = 0;
		bs->stream_sequence =  g_list_append(bs->stream_sequence, sc);
		bs->streams[dir].stream_chunks = g_list_append(bs->streams[dir].stream_chunks, sc);

	}else
	if (lastbistreamsc == laststreamsc && lastbistreamsc != NULL)
	{
		g_string_append_len(laststreamsc->data, data, size);
	}else
	{
		uint32_t stream_offset = 0;
		uint32_t bistream_offset = 0;

		if (laststreamsc != NULL)
			stream_offset = laststreamsc->stream_offset + laststreamsc->data->len;

		if (lastbistreamsc != NULL)
			bistream_offset = lastbistreamsc->bistream_offset + lastbistreamsc->data->len;

		struct stream_chunk *sc = stream_chunk_new(data, size, dir);
		sc->bistream_offset = bistream_offset;
		sc->stream_offset = stream_offset;

		bs->stream_sequence =  g_list_append(bs->stream_sequence, sc);
		bs->streams[dir].stream_chunks = g_list_append(bs->streams[dir].stream_chunks, sc);
	}

	g_mutex_unlock(bs->streams[dir].mutex);
	g_mutex_unlock(bs->mutex);
}

void print_stream_chunk2(struct stream_chunk *sc)
{
	int c;
	uint32_t stream_offset = sc->stream_offset;
	uint32_t bistream_offset = sc->bistream_offset;
	char buf[256];
	int off=0;
	for (c=0;c<sc->data->len; c+=16)
	{
		off += sprintf(buf, "0x%04x | ", bistream_offset + c);
		if (sc->direction == bistream_out)
			off += sprintf(buf+off, "%49s", " ");

		int i;
		for (i=0;i<16;i++)
		{
			if (i+c < sc->data->len)
				off += sprintf(buf+off, "%02x ", ((unsigned char *)sc->data->str)[c+i]);
			else
				off += sprintf(buf+off, "   ");
		}

		if (sc->direction == bistream_in)
			off += sprintf(buf+off,"%49s", " ");

		off += sprintf(buf+off, "  | ");

		for (i=0;i<16;i++)
		{
			if (i+c < sc->data->len)
			{
				if (isprint(((unsigned char *)sc->data->str)[c+i]) )
					off += sprintf(buf+off, "%c", ((unsigned char *)sc->data->str)[c+i]);
				else
					off += sprintf(buf+off, ".");
			}else
			{
				off += sprintf(buf+off, " ");
			}

		}
		off += sprintf(buf+off," | 0x%04x ", stream_offset + c );
		g_debug("%s", buf);
		off = 0;
	}
}



void print_stream_chunk(struct stream_chunk *sc)
{
	int c;
	uint32_t stream_offset = sc->stream_offset;
	uint32_t bistream_offset = sc->bistream_offset;

	for (c=0;c<sc->data->len; c+=16)
	{
		printf("0x%04x | ", bistream_offset + c);
		if (sc->direction == bistream_out)
			printf("%49s", " ");

		int i;
		for (i=0;i<16;i++)
		{
			if (i+c < sc->data->len)
				printf("%02x ", ((unsigned char *)sc->data->str)[c+i]);
			else
				printf("   ");
		}

		if (sc->direction == bistream_in)
			printf("%49s", " ");

		printf("  | ");
		for (i=0;i<16;i++)
		{
			if (i+c < sc->data->len)
			{
				if (isprint(((unsigned char *)sc->data->str)[c+i]) )
					printf("%c", ((unsigned char *)sc->data->str)[c+i]);
				else
					printf(".");
			}else
				printf(" ");

		}
		printf(" | 0x%04x ", stream_offset + c );
		printf("\n");
	}
}

void bistream_debug(struct bistream *bs)
{
	GList *it;
	g_mutex_lock(bs->mutex);
	for (it = g_list_first(bs->stream_sequence); it != NULL; it = g_list_next(it))
	{
		print_stream_chunk2(it->data);
	}
	g_mutex_unlock(bs->mutex);
}

uint32_t sizeof_stream_chunks(GList *stream_chunks)
{
	GList *it;
	uint32_t size = 0;
	for (it = g_list_first(stream_chunks); it != NULL; it = g_list_next(it))
		size += ((struct stream_chunk *)it)->data->len;
	return size;
}

int32_t bistream_get_stream(struct bistream *bs, enum bistream_direction dir, uint32_t start, int32_t end, void **data)
{
	g_debug("%s bs %p dir %i start %i end %i data %p", __PRETTY_FUNCTION__, bs, dir, start, end, data);
//	start = 0;
	g_mutex_lock(bs->streams[dir].mutex);
	GList *last = g_list_last(bs->streams[dir].stream_chunks);
	GList *first = g_list_first(bs->streams[dir].stream_chunks);

	if (!first || !last)
	{
		g_mutex_unlock(bs->streams[dir].mutex);
		return -1;
	}

	struct stream_chunk *lastsc = last->data;


	if (end == -1)
		end = lastsc->stream_offset + lastsc->data->len;
/*
	printf("end %i\n",  end);
	printf("lastsc->... %i\n", lastsc->stream_offset);
	printf("lastsc->... %i\n", (int)lastsc->data->len);
	printf("start %i\n", start);
*/
	if (end > lastsc->stream_offset + lastsc->data->len || start >= end)
	{
		g_mutex_unlock(bs->streams[dir].mutex);
		return -1;
	}


	*data = g_malloc0(end - start + 1 );

	GList *it = first;
	struct stream_chunk *itsc = it->data;


	while(itsc->stream_offset != start && itsc->stream_offset + itsc->data->len <= start)
	{
		g_debug("itsc %p offset %i size %i", itsc,  itsc->stream_offset, (int)itsc->data->len);
        it = g_list_next(it);
		itsc = it->data;
	}

	g_debug("found stream begin %p stream_offset %i size %i", itsc,  itsc->stream_offset, (int)itsc->data->len);

	int32_t offset = 0;
	while(itsc->stream_offset < end)
	{
		itsc = it->data;
		uint32_t start_offset = 0;
		uint32_t end_offset = itsc->data->len-1;

		if (itsc->stream_offset < start)
			start_offset = start - itsc->stream_offset;

		if (itsc->stream_offset + itsc->data->len > end)
			end_offset = end - itsc->stream_offset;

		int32_t size = end_offset - start_offset;
		g_debug("copy data %p stream_offset %i size %i copy_start %i copy_end %i size %i", itsc,  itsc->stream_offset, (int)itsc->data->len, start_offset, end_offset, size);

		memcpy(*data + offset, itsc->data->str + start_offset, size);

		offset+=size;

		it = g_list_next(it);
		if (it == NULL)
			break;
	}
	g_mutex_unlock(bs->streams[dir].mutex);
	return end - start;
}

