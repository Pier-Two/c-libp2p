#include "gossipsub_proto.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "libp2p/log.h"
#include "libp2p/stream.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "noise/protobufs.h"
#include "noise/protocol/constants.h"
#include "peer_id/peer_id.h"
#include "protocol/gossipsub/message.h"
#include "gossipsub_rpc.pb.h"

#define GOSSIPSUB_PROTO_MODULE "gossipsub_proto"
/* No fixed size cap in the gossipsub specs; leave unlimited by default. */
#define GOSSIPSUB_RPC_DEFAULT_MAX SIZE_MAX

enum
{
	GOSSIPSUB_STREAM_KEY = 0,
	GOSSIPSUB_STREAM_LEN,
	GOSSIPSUB_STREAM_VALUE,
	GOSSIPSUB_STREAM_SKIP_VARINT,
	GOSSIPSUB_STREAM_SKIP_BYTES
};

static inline int varint_is_minimal(uint64_t v, size_t len)
{
	if (len == 0 || len > 10)
		return 0;
	uint8_t tmp[10];
	size_t needed = 0;
	if (unsigned_varint_encode(v, tmp, sizeof(tmp), &needed) != UNSIGNED_VARINT_OK)
		return 0;
	return needed == len;
}

static libp2p_err_t gossipsub_read_lp_frame(libp2p_stream_t *stream, uint8_t **out_buf, size_t *out_len)
{
	if (!stream || !out_buf || !out_len)
		return LIBP2P_ERR_NULL_PTR;

	/* Default stall timeout per stage (header/payload). */
	const uint64_t slow_ms = 2000;

	uint8_t hdr[10];
	size_t used = 0;
	uint64_t need = 0;
	size_t consumed = 0;
	uint64_t start = now_mono_ms();

	/* Read varint header byte-by-byte; tolerate EAGAIN while making progress. */
	while (used < sizeof(hdr))
	{
		uint64_t elapsed = now_mono_ms() - start;
		uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
		if (used > 0 && remain == 0)
			return LIBP2P_ERR_TIMEOUT;
		if (remain)
			(void)libp2p_stream_set_deadline(stream, remain);

		ssize_t n = libp2p_stream_read(stream, &hdr[used], 1);
		if (n == 1)
		{
			used += 1;
			start = now_mono_ms();
			if (unsigned_varint_decode(hdr, used, &need, &consumed) == UNSIGNED_VARINT_OK)
				break; /* got full length */
			continue;
		}
		if (n == LIBP2P_ERR_AGAIN)
		{
			if (used == 0)
				return LIBP2P_ERR_AGAIN; /* no progress yet; let caller interleave */
			continue;			 /* keep blocking until header complete or timeout */
		}
		/* EOF or fatal */
		return (libp2p_err_t)n;
	}

	if (used == sizeof(hdr) && unsigned_varint_decode(hdr, used, &need, &consumed) != UNSIGNED_VARINT_OK)
		return LIBP2P_ERR_INTERNAL;
	if (!varint_is_minimal(need, consumed))
		return LIBP2P_ERR_INTERNAL;
	if (need > SIZE_MAX)
		return LIBP2P_ERR_MSG_TOO_LARGE;

	size_t frame_len = (size_t)need;
	uint8_t *buffer = (uint8_t *)malloc(frame_len > 0 ? frame_len : 1u);
	if (!buffer)
		return LIBP2P_ERR_INTERNAL;

	/* Read payload with EAGAIN tolerance */
	size_t got = 0;
	start = now_mono_ms();
	while (got < frame_len)
	{
		uint64_t elapsed = now_mono_ms() - start;
		uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
		if (remain == 0)
		{
			free(buffer);
			return LIBP2P_ERR_TIMEOUT;
		}
		(void)libp2p_stream_set_deadline(stream, remain);

		ssize_t n = libp2p_stream_read(stream, buffer + got, frame_len - got);
		if (n > 0)
		{
			got += (size_t)n;
			start = now_mono_ms();
			continue;
		}
		if (n == LIBP2P_ERR_AGAIN)
			continue;
		free(buffer);
		return (libp2p_err_t)n; /* EOF/fatal */
	}
	(void)libp2p_stream_set_deadline(stream, 0);

	*out_buf = buffer;
	*out_len = frame_len;
	return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_rpc_encode_publish(const libp2p_gossipsub_message_t *msg, uint8_t **out_buf,
						 size_t *out_len)
{
	if (!msg || !msg->topic.topic || !out_buf || !out_len)
		return LIBP2P_ERR_NULL_PTR;

	*out_buf = NULL;
	*out_len = 0;

	libp2p_gossipsub_RPC *rpc = NULL;
	libp2p_err_t result = LIBP2P_ERR_INTERNAL;
	uint8_t *buffer = NULL;

	int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
	if (noise_rc != NOISE_ERROR_NONE || !rpc)
		goto cleanup;

	libp2p_gossipsub_Message *proto_msg = NULL;
	noise_rc = libp2p_gossipsub_RPC_add_publish(rpc, &proto_msg);
	if (noise_rc != NOISE_ERROR_NONE || !proto_msg)
		goto cleanup;

	const char *topic = msg->topic.topic;
	size_t topic_len = strlen(topic);
	if (topic_len == 0)
	{
		result = LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}
	noise_rc = libp2p_gossipsub_Message_set_topic(proto_msg, topic, topic_len);
	if (noise_rc != NOISE_ERROR_NONE)
		goto cleanup;

	noise_rc = libp2p_gossipsub_Message_add_topic_ids(proto_msg, topic, topic_len);
	if (noise_rc != NOISE_ERROR_NONE)
		goto cleanup;

	if (msg->data && msg->data_len)
	{
		noise_rc = libp2p_gossipsub_Message_set_data(proto_msg, msg->data, msg->data_len);
		if (noise_rc != NOISE_ERROR_NONE)
			goto cleanup;
	}

	if (msg->seqno && msg->seqno_len)
	{
		noise_rc = libp2p_gossipsub_Message_set_seqno(proto_msg, msg->seqno, msg->seqno_len);
		if (noise_rc != NOISE_ERROR_NONE)
			goto cleanup;
	}

	if (msg->from)
	{
		const uint8_t *from_bytes = NULL;
		size_t from_len = 0;
		if (peer_id_multihash_view(msg->from, &from_bytes, &from_len) == PEER_ID_OK && from_len > 0)
		{
			noise_rc = libp2p_gossipsub_Message_set_from(proto_msg, from_bytes, from_len);
			if (noise_rc != NOISE_ERROR_NONE)
				goto cleanup;
		}
	}

	NoiseProtobuf measure;
	noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
	if (noise_rc != NOISE_ERROR_NONE)
		goto cleanup;
	noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
	if (noise_rc != NOISE_ERROR_NONE)
		goto cleanup;
	size_t encoded_size = 0;
	noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
	if (noise_rc != NOISE_ERROR_NONE)
		goto cleanup;
	if (encoded_size == 0)
	{
		result = LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}

	buffer = (uint8_t *)malloc(encoded_size);
	if (!buffer)
	{
		result = LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}

	NoiseProtobuf out_pb;
	noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
	if (noise_rc != NOISE_ERROR_NONE)
	{
		result = LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}
	noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
	if (noise_rc != NOISE_ERROR_NONE)
	{
		result = LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}

	uint8_t *encoded = NULL;
	size_t encoded_len = 0;
	noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
	if (noise_rc != NOISE_ERROR_NONE || !encoded)
	{
		result = (noise_rc == NOISE_ERROR_INVALID_LENGTH) ? LIBP2P_ERR_MSG_TOO_LARGE : LIBP2P_ERR_INTERNAL;
		goto cleanup;
	}

	*out_buf = encoded;
	*out_len = encoded_len;
	buffer = NULL; /* ownership transferred */
	result = LIBP2P_ERR_OK;

	if (encoded && encoded_len)
	{
		libp2p_log_level_t log_level;
		if (libp2p_log_is_enabled(LIBP2P_LOG_TRACE))
			log_level = LIBP2P_LOG_TRACE;
		else if (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG))
			log_level = LIBP2P_LOG_DEBUG;
		else
			log_level = (libp2p_log_level_t)-1;

		if (log_level != (libp2p_log_level_t)-1 && log_level != LIBP2P_LOG_ERROR)
		{
			static const char hex_digits[] = "0123456789abcdef";
			const size_t preview_cap = 48;
			char preview[(preview_cap * 2) + 4];
			size_t preview_len = encoded_len < preview_cap ? encoded_len : preview_cap;
			for (size_t i = 0; i < preview_len; ++i)
			{
				preview[(i * 2) + 0] = hex_digits[(encoded[i] >> 4) & 0xF];
				preview[(i * 2) + 1] = hex_digits[encoded[i] & 0xF];
			}
			size_t preview_idx = preview_len * 2;
			preview[preview_idx] = '\0';
			if (encoded_len > preview_cap)
			{
				preview[preview_idx++] = '.';
				preview[preview_idx++] = '.';
				preview[preview_idx++] = '.';
				preview[preview_idx] = '\0';
			}

			size_t from_len = 0;
			const uint8_t *from_bytes = NULL;
			if (msg->from)
				(void)peer_id_multihash_view(msg->from, &from_bytes, &from_len);
			LP_LOGF(log_level, GOSSIPSUB_PROTO_MODULE,
				"encode publish topic=%s data_len=%zu seqno_len=%zu from_len=%zu frame_len=%zu "
				"preview=%s",
				msg->topic.topic ? msg->topic.topic : "(null)", msg->data_len, msg->seqno_len, from_len,
				encoded_len, preview);
		}
	}

cleanup:
	if (buffer)
	{
		free(buffer);
		buffer = NULL;
	}

	if (rpc)
		libp2p_gossipsub_RPC_free(rpc);

	if (result != LIBP2P_ERR_OK)
	{
		*out_buf = NULL;
		*out_len = 0;
		if (noise_rc != NOISE_ERROR_NONE)
			LP_LOGW(GOSSIPSUB_PROTO_MODULE, "noise protobuf encode failed (rc=%d)", noise_rc);
	}

	return result;
}

static libp2p_err_t convert_noise_err(int noise_err)
{
	if (noise_err == NOISE_ERROR_NONE)
		return LIBP2P_ERR_OK;
	if (noise_err == NOISE_ERROR_INVALID_LENGTH)
		return LIBP2P_ERR_MSG_TOO_LARGE;
	return LIBP2P_ERR_INTERNAL;
}

libp2p_err_t libp2p_gossipsub_rpc_decode_frame(const uint8_t *frame, size_t frame_len, libp2p_gossipsub_RPC **out_rpc)
{
	if (!out_rpc)
		return LIBP2P_ERR_NULL_PTR;
	*out_rpc = NULL;

	if (frame_len > 0 && !frame)
		return LIBP2P_ERR_NULL_PTR;

	NoiseProtobuf in_pb;
	int noise_rc = noise_protobuf_prepare_input(&in_pb, (uint8_t *)frame, frame_len);
	if (noise_rc != NOISE_ERROR_NONE)
		return convert_noise_err(noise_rc);

	libp2p_gossipsub_RPC *rpc = NULL;
	noise_rc = libp2p_gossipsub_RPC_read(&in_pb, 0, &rpc);
	if (noise_rc != NOISE_ERROR_NONE || !rpc)
	{
		noise_protobuf_finish_input(&in_pb);
		return convert_noise_err(noise_rc);
	}

	noise_rc = noise_protobuf_finish_input(&in_pb);
	if (noise_rc != NOISE_ERROR_NONE)
	{
		libp2p_gossipsub_RPC_free(rpc);
		return convert_noise_err(noise_rc);
	}

	*out_rpc = rpc;
	return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_rpc_read_stream(libp2p_stream_t *stream, uint8_t **out_buf, size_t *out_len,
					      libp2p_gossipsub_RPC **out_rpc)
{
	if (!stream)
		return LIBP2P_ERR_NULL_PTR;
	if (!out_buf && !out_rpc && !out_len)
		return LIBP2P_ERR_NULL_PTR;

	uint8_t *buffer = NULL;
	size_t frame_len = 0;
	libp2p_err_t read_rc = gossipsub_read_lp_frame(stream, &buffer, &frame_len);
	if (read_rc != LIBP2P_ERR_OK)
		return read_rc;
	libp2p_gossipsub_RPC *rpc = NULL;
	if (out_rpc)
	{
		libp2p_err_t derr = libp2p_gossipsub_rpc_decode_frame(buffer, frame_len, &rpc);
		if (derr != LIBP2P_ERR_OK)
		{
			free(buffer);
			return derr;
		}
	}

	if (out_len)
		*out_len = frame_len;

	if (out_buf)
		*out_buf = buffer;
	else
	{
		free(buffer);
	}

	if (out_rpc)
		*out_rpc = rpc;
	else if (rpc)
		libp2p_gossipsub_RPC_free(rpc);

	return LIBP2P_ERR_OK;
}

void libp2p_gossipsub_rpc_decoder_init(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return;
	memset(dec, 0, sizeof(*dec));
	dec->max_frame_len = GOSSIPSUB_RPC_DEFAULT_MAX;
	LP_LOGT(GOSSIPSUB_PROTO_MODULE, "decoder init max=%zu", dec->max_frame_len);
}

void libp2p_gossipsub_rpc_decoder_reset(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return;
	dec->header_used = 0;
	dec->have_length = 0;
	dec->frame_len = 0;
	dec->frame_used = 0;
	dec->field_header_used = 0;
	dec->field_number = 0;
	dec->field_wire_type = 0;
	dec->field_len = 0;
	dec->field_used = 0;
	dec->skip_remaining = 0;
	dec->stream_state = GOSSIPSUB_STREAM_KEY;
	if (dec->field_buf)
	{
		free(dec->field_buf);
		dec->field_buf = NULL;
	}
	dec->field_cap = 0;
	if (dec->stream_rpc)
	{
		libp2p_gossipsub_RPC_free(dec->stream_rpc);
		dec->stream_rpc = NULL;
	}
	if (dec->stream_control_rpc)
	{
		libp2p_gossipsub_RPC_free(dec->stream_control_rpc);
		dec->stream_control_rpc = NULL;
	}
}

void libp2p_gossipsub_rpc_decoder_free(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return;
	libp2p_gossipsub_rpc_decoder_reset(dec);
	if (dec->frame_buf)
	{
		free(dec->frame_buf);
		dec->frame_buf = NULL;
	}
	dec->frame_cap = 0;
}

void libp2p_gossipsub_rpc_decoder_set_max_frame(libp2p_gossipsub_rpc_decoder_t *dec, size_t max_frame_len)
{
	if (!dec)
		return;
	dec->max_frame_len = (max_frame_len > 0) ? max_frame_len : GOSSIPSUB_RPC_DEFAULT_MAX;
	if (dec->frame_cap > dec->max_frame_len)
	{
		uint8_t *new_buf = (uint8_t *)realloc(dec->frame_buf, dec->max_frame_len);
		if (new_buf)
		{
			dec->frame_buf = new_buf;
			dec->frame_cap = dec->max_frame_len;
		}
		else
		{
			/* If we fail to shrink, leave buffer as-is but clamp advertised cap. */
			dec->frame_cap = dec->frame_cap > dec->max_frame_len ? dec->max_frame_len : dec->frame_cap;
		}
	}
}

static libp2p_err_t gossipsub_decoder_emit(libp2p_gossipsub_rpc_decoder_t *dec, libp2p_gossipsub_rpc_decoder_cb cb,
					   void *user_data)
{
	const uint8_t *frame = (dec->frame_len > 0) ? dec->frame_buf : NULL;
	libp2p_err_t rc = LIBP2P_ERR_OK;
	if (cb)
		rc = cb(frame, dec->frame_len, user_data);
	dec->have_length = 0;
	dec->frame_len = 0;
	dec->frame_used = 0;
	dec->header_used = 0;
	return rc;
}

static libp2p_err_t gossipsub_decoder_fail(libp2p_gossipsub_rpc_decoder_t *dec, libp2p_err_t rc)
{
	libp2p_gossipsub_rpc_decoder_reset(dec);
	return rc;
}

libp2p_err_t libp2p_gossipsub_rpc_decoder_feed(libp2p_gossipsub_rpc_decoder_t *dec, const uint8_t *data, size_t len,
					       libp2p_gossipsub_rpc_decoder_cb cb, void *user_data)
{
	if (!dec || (len > 0 && !data))
		return LIBP2P_ERR_NULL_PTR;

	size_t idx = 0;
	while (idx < len)
	{
		if (!dec->have_length)
		{
			if (dec->header_used >= sizeof(dec->header))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);

			dec->header[dec->header_used++] = data[idx++];
			uint64_t frame_len64 = 0;
			size_t consumed = 0;
			unsigned_varint_err_t var_rc =
				unsigned_varint_decode(dec->header, dec->header_used, &frame_len64, &consumed);
			if (var_rc == UNSIGNED_VARINT_ERR_TOO_LONG)
			{
				if (dec->header_used < sizeof(dec->header))
					continue;
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			}
			if (var_rc != UNSIGNED_VARINT_OK)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			if (!varint_is_minimal(frame_len64, consumed))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			if (frame_len64 > dec->max_frame_len || frame_len64 > SIZE_MAX)
			{
				LP_LOGW(GOSSIPSUB_PROTO_MODULE,
					"decoder frame too large (len=%" PRIu64 " max=%zu header_used=%zu)",
					frame_len64, dec->max_frame_len, dec->header_used);
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_MSG_TOO_LARGE);
			}

			dec->frame_len = (size_t)frame_len64;
			dec->frame_used = 0;
			dec->have_length = 1;
			dec->header_used = 0;

			if (dec->frame_len > 0)
			{
				if (dec->frame_len > dec->frame_cap)
				{
					uint8_t *new_buf = (uint8_t *)realloc(dec->frame_buf, dec->frame_len);
					if (!new_buf)
						return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
					dec->frame_buf = new_buf;
					dec->frame_cap = dec->frame_len;
				}
			}
			else
			{
				libp2p_err_t emit_rc = gossipsub_decoder_emit(dec, cb, user_data);
				if (emit_rc != LIBP2P_ERR_OK)
					return emit_rc;
			}
			continue;
		}

		if (dec->frame_len == 0)
		{
			libp2p_err_t emit_rc = gossipsub_decoder_emit(dec, cb, user_data);
			if (emit_rc != LIBP2P_ERR_OK)
				return emit_rc;
			continue;
		}

		size_t want = dec->frame_len - dec->frame_used;
		size_t chunk = len - idx;
		if (chunk > want)
			chunk = want;
		if (chunk > 0)
		{
			memcpy(dec->frame_buf + dec->frame_used, data + idx, chunk);
			dec->frame_used += chunk;
			idx += chunk;
		}

		if (dec->frame_used == dec->frame_len)
		{
			libp2p_err_t emit_rc = gossipsub_decoder_emit(dec, cb, user_data);
			if (emit_rc != LIBP2P_ERR_OK)
				return emit_rc;
		}
	}

	return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_decoder_prepare_stream_frame(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;
	if (dec->stream_rpc)
		libp2p_gossipsub_RPC_free(dec->stream_rpc);
	dec->stream_rpc = NULL;
	if (libp2p_gossipsub_RPC_new(&dec->stream_rpc) != NOISE_ERROR_NONE || !dec->stream_rpc)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	dec->field_header_used = 0;
	dec->field_number = 0;
	dec->field_wire_type = 0;
	dec->field_len = 0;
	dec->field_used = 0;
	dec->skip_remaining = 0;
	dec->stream_state = GOSSIPSUB_STREAM_KEY;
	return LIBP2P_ERR_OK;
}

static void gossipsub_decoder_release_field_buf(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return;
	if (dec->field_buf)
	{
		free(dec->field_buf);
		dec->field_buf = NULL;
	}
	dec->field_cap = 0;
	dec->field_len = 0;
	dec->field_used = 0;
	dec->field_number = 0;
	dec->field_wire_type = 0;
	dec->field_header_used = 0;
}

static libp2p_err_t gossipsub_decoder_finish_noise_input(NoiseProtobuf *pb, void *obj,
							 void (*free_fn)(void *))
{
	int noise_rc = noise_protobuf_finish_input(pb);
	if (noise_rc == NOISE_ERROR_NONE)
		return LIBP2P_ERR_OK;
	if (obj && free_fn)
		free_fn(obj);
	return convert_noise_err(noise_rc);
}

static void gossipsub_decoder_free_subopt(void *obj)
{
	libp2p_gossipsub_RPC_SubOpts_free((libp2p_gossipsub_RPC_SubOpts *)obj);
}

static void gossipsub_decoder_free_message(void *obj)
{
	libp2p_gossipsub_Message_free((libp2p_gossipsub_Message *)obj);
}

static libp2p_err_t gossipsub_decoder_parse_control_rpc(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;

	uint8_t len_buf[10];
	size_t len_buf_len = 0;
	if (unsigned_varint_encode(dec->field_len, len_buf, sizeof(len_buf), &len_buf_len) != UNSIGNED_VARINT_OK)
		return LIBP2P_ERR_INTERNAL;

	size_t control_frame_len = 1 + len_buf_len + dec->field_len;
	uint8_t *control_frame = (uint8_t *)malloc(control_frame_len > 0 ? control_frame_len : 1u);
	if (!control_frame)
		return LIBP2P_ERR_INTERNAL;
	control_frame[0] = (uint8_t)((3u << 3) | 2u);
	memcpy(control_frame + 1, len_buf, len_buf_len);
	if (dec->field_len > 0)
		memcpy(control_frame + 1 + len_buf_len, dec->field_buf, dec->field_len);

	libp2p_gossipsub_RPC *control_rpc = NULL;
	libp2p_err_t rc = libp2p_gossipsub_rpc_decode_frame(control_frame, control_frame_len, &control_rpc);
	free(control_frame);
	if (rc != LIBP2P_ERR_OK)
		return rc;

	if (dec->stream_control_rpc)
		libp2p_gossipsub_RPC_free(dec->stream_control_rpc);
	dec->stream_control_rpc = control_rpc;
	return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_decoder_parse_stream_field(libp2p_gossipsub_rpc_decoder_t *dec)
{
	if (!dec || !dec->stream_rpc)
		return LIBP2P_ERR_NULL_PTR;
	if (dec->field_number != 1 && dec->field_number != 2 && dec->field_number != 3)
		return LIBP2P_ERR_OK;
	if (dec->field_number == 3)
		return gossipsub_decoder_parse_control_rpc(dec);

	uint8_t empty = 0;
	uint8_t *input = dec->field_len > 0 ? dec->field_buf : &empty;
	if (dec->field_len > 0 && !input)
		return LIBP2P_ERR_NULL_PTR;

	NoiseProtobuf pb;
	int noise_rc = noise_protobuf_prepare_input(&pb, input, dec->field_len);
	if (noise_rc != NOISE_ERROR_NONE)
		return convert_noise_err(noise_rc);

	if (dec->field_number == 1)
	{
		libp2p_gossipsub_RPC_SubOpts *sub = NULL;
		noise_rc = libp2p_gossipsub_RPC_SubOpts_read(&pb, 0, &sub);
		if (noise_rc != NOISE_ERROR_NONE || !sub)
		{
			noise_protobuf_finish_input(&pb);
			if (sub)
				libp2p_gossipsub_RPC_SubOpts_free(sub);
			return convert_noise_err(noise_rc);
		}
		libp2p_err_t finish_rc = gossipsub_decoder_finish_noise_input(&pb, sub, gossipsub_decoder_free_subopt);
		if (finish_rc != LIBP2P_ERR_OK)
			return finish_rc;
		noise_rc = libp2p_gossipsub_RPC_insert_subscriptions(
			dec->stream_rpc, libp2p_gossipsub_RPC_count_subscriptions(dec->stream_rpc), sub);
		if (noise_rc != NOISE_ERROR_NONE)
		{
			libp2p_gossipsub_RPC_SubOpts_free(sub);
			return convert_noise_err(noise_rc);
		}
		return LIBP2P_ERR_OK;
	}

	if (dec->field_number == 2)
	{
		libp2p_gossipsub_Message *msg = NULL;
		noise_rc = libp2p_gossipsub_Message_read(&pb, 0, &msg);
		if (noise_rc != NOISE_ERROR_NONE || !msg)
		{
			noise_protobuf_finish_input(&pb);
			if (msg)
				libp2p_gossipsub_Message_free(msg);
			return convert_noise_err(noise_rc);
		}
		libp2p_err_t finish_rc = gossipsub_decoder_finish_noise_input(&pb, msg, gossipsub_decoder_free_message);
		if (finish_rc != LIBP2P_ERR_OK)
			return finish_rc;
		noise_rc = libp2p_gossipsub_RPC_insert_publish(
			dec->stream_rpc, libp2p_gossipsub_RPC_count_publish(dec->stream_rpc), msg);
		if (noise_rc != NOISE_ERROR_NONE)
		{
			libp2p_gossipsub_Message_free(msg);
			return convert_noise_err(noise_rc);
		}
		return LIBP2P_ERR_OK;
	}
	return LIBP2P_ERR_INTERNAL;
}

static libp2p_err_t gossipsub_decoder_emit_rpc(libp2p_gossipsub_rpc_decoder_t *dec,
					       libp2p_gossipsub_rpc_decoder_rpc_cb cb, void *user_data)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;

	libp2p_gossipsub_RPC *rpc = dec->stream_rpc;
	libp2p_gossipsub_RPC *control_rpc = dec->stream_control_rpc;
	dec->stream_rpc = NULL;
	dec->stream_control_rpc = NULL;
	size_t frame_len = dec->frame_len;
	libp2p_err_t rc = LIBP2P_ERR_OK;
	if (cb)
		rc = cb(rpc, control_rpc, frame_len, user_data);
	if (rpc)
		libp2p_gossipsub_RPC_free(rpc);
	if (control_rpc)
		libp2p_gossipsub_RPC_free(control_rpc);
	libp2p_gossipsub_rpc_decoder_reset(dec);
	return rc;
}

static libp2p_err_t gossipsub_decoder_complete_stream_frame(libp2p_gossipsub_rpc_decoder_t *dec,
							    libp2p_gossipsub_rpc_decoder_rpc_cb cb,
							    void *user_data)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;
	if (dec->stream_state != GOSSIPSUB_STREAM_KEY || dec->field_header_used != 0 || dec->skip_remaining != 0 ||
	    dec->field_buf != NULL)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	return gossipsub_decoder_emit_rpc(dec, cb, user_data);
}

static libp2p_err_t gossipsub_decoder_stream_finish_field(libp2p_gossipsub_rpc_decoder_t *dec)
{
	libp2p_err_t rc = gossipsub_decoder_parse_stream_field(dec);
	gossipsub_decoder_release_field_buf(dec);
	if (rc != LIBP2P_ERR_OK)
		return gossipsub_decoder_fail(dec, rc);
	dec->stream_state = GOSSIPSUB_STREAM_KEY;
	return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_decoder_stream_set_skip(libp2p_gossipsub_rpc_decoder_t *dec, size_t bytes)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;
	if (bytes > dec->frame_len - dec->frame_used)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	dec->skip_remaining = bytes;
	dec->stream_state = bytes > 0 ? GOSSIPSUB_STREAM_SKIP_BYTES : GOSSIPSUB_STREAM_KEY;
	return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_decoder_stream_key_complete(libp2p_gossipsub_rpc_decoder_t *dec, uint64_t key,
							  size_t consumed)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;
	if (!varint_is_minimal(key, consumed))
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);

	uint64_t field_number = key >> 3;
	uint8_t wire_type = (uint8_t)(key & 0x7u);
	if (field_number == 0 || field_number > UINT32_MAX)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);

	dec->field_header_used = 0;
	dec->field_number = (uint32_t)field_number;
	dec->field_wire_type = wire_type;

	if (field_number == 1 || field_number == 2 || field_number == 3)
	{
		if (wire_type != 2)
			return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
		dec->stream_state = GOSSIPSUB_STREAM_LEN;
		return LIBP2P_ERR_OK;
	}

	switch (wire_type)
	{
	case 0:
		dec->stream_state = GOSSIPSUB_STREAM_SKIP_VARINT;
		return LIBP2P_ERR_OK;
	case 1:
		return gossipsub_decoder_stream_set_skip(dec, 8);
	case 2:
		dec->stream_state = GOSSIPSUB_STREAM_LEN;
		return LIBP2P_ERR_OK;
	case 5:
		return gossipsub_decoder_stream_set_skip(dec, 4);
	default:
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	}
}

static libp2p_err_t gossipsub_decoder_stream_len_complete(libp2p_gossipsub_rpc_decoder_t *dec, uint64_t length,
							  size_t consumed)
{
	if (!dec)
		return LIBP2P_ERR_NULL_PTR;
	if (!varint_is_minimal(length, consumed))
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	if (length > SIZE_MAX || length > dec->frame_len - dec->frame_used)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_MSG_TOO_LARGE);

	dec->field_header_used = 0;
	dec->field_len = (size_t)length;
	dec->field_used = 0;

	if (dec->field_number != 1 && dec->field_number != 2 && dec->field_number != 3)
		return gossipsub_decoder_stream_set_skip(dec, dec->field_len);

	if (dec->field_len == 0)
		return gossipsub_decoder_stream_finish_field(dec);

	dec->field_buf = (uint8_t *)malloc(dec->field_len);
	if (!dec->field_buf)
		return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
	dec->field_cap = dec->field_len;
	dec->stream_state = GOSSIPSUB_STREAM_VALUE;
	return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_rpc_decoder_feed_decoded(libp2p_gossipsub_rpc_decoder_t *dec, const uint8_t *data,
						       size_t len, libp2p_gossipsub_rpc_decoder_rpc_cb cb,
						       void *user_data)
{
	if (!dec || (len > 0 && !data))
		return LIBP2P_ERR_NULL_PTR;

	size_t idx = 0;
	while (idx < len)
	{
		if (!dec->have_length)
		{
			if (dec->header_used >= sizeof(dec->header))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);

			dec->header[dec->header_used++] = data[idx++];
			uint64_t frame_len64 = 0;
			size_t consumed = 0;
			unsigned_varint_err_t var_rc =
				unsigned_varint_decode(dec->header, dec->header_used, &frame_len64, &consumed);
			if (var_rc == UNSIGNED_VARINT_ERR_TOO_LONG)
			{
				if (dec->header_used < sizeof(dec->header))
					continue;
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			}
			if (var_rc != UNSIGNED_VARINT_OK)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			if (!varint_is_minimal(frame_len64, consumed))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			if (frame_len64 > dec->max_frame_len || frame_len64 > SIZE_MAX)
			{
				LP_LOGW(GOSSIPSUB_PROTO_MODULE,
					"stream decoder frame too large (len=%" PRIu64 " max=%zu header_used=%zu)",
					frame_len64, dec->max_frame_len, dec->header_used);
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_MSG_TOO_LARGE);
			}

			dec->frame_len = (size_t)frame_len64;
			dec->frame_used = 0;
			dec->have_length = 1;
			dec->header_used = 0;

			libp2p_err_t prep_rc = gossipsub_decoder_prepare_stream_frame(dec);
			if (prep_rc != LIBP2P_ERR_OK)
				return prep_rc;
			if (dec->frame_len == 0)
			{
				libp2p_err_t emit_rc = gossipsub_decoder_emit_rpc(dec, cb, user_data);
				if (emit_rc != LIBP2P_ERR_OK)
					return emit_rc;
			}
			continue;
		}

		if (dec->frame_used == dec->frame_len)
		{
			libp2p_err_t emit_rc = gossipsub_decoder_complete_stream_frame(dec, cb, user_data);
			if (emit_rc != LIBP2P_ERR_OK)
				return emit_rc;
			continue;
		}

		switch (dec->stream_state)
		{
		case GOSSIPSUB_STREAM_KEY: {
			if (dec->field_header_used >= sizeof(dec->field_header))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			dec->field_header[dec->field_header_used++] = data[idx++];
			dec->frame_used++;
			uint64_t key = 0;
			size_t consumed = 0;
			unsigned_varint_err_t var_rc =
				unsigned_varint_decode(dec->field_header, dec->field_header_used, &key, &consumed);
			if (var_rc == UNSIGNED_VARINT_ERR_TOO_LONG)
			{
				if (dec->field_header_used < sizeof(dec->field_header))
					continue;
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			}
			if (var_rc != UNSIGNED_VARINT_OK)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			libp2p_err_t key_rc = gossipsub_decoder_stream_key_complete(dec, key, consumed);
			if (key_rc != LIBP2P_ERR_OK)
				return key_rc;
			break;
		}
		case GOSSIPSUB_STREAM_LEN: {
			if (dec->field_header_used >= sizeof(dec->field_header))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			dec->field_header[dec->field_header_used++] = data[idx++];
			dec->frame_used++;
			uint64_t length = 0;
			size_t consumed = 0;
			unsigned_varint_err_t var_rc =
				unsigned_varint_decode(dec->field_header, dec->field_header_used, &length, &consumed);
			if (var_rc == UNSIGNED_VARINT_ERR_TOO_LONG)
			{
				if (dec->field_header_used < sizeof(dec->field_header))
					continue;
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			}
			if (var_rc != UNSIGNED_VARINT_OK)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			libp2p_err_t len_rc = gossipsub_decoder_stream_len_complete(dec, length, consumed);
			if (len_rc != LIBP2P_ERR_OK)
				return len_rc;
			break;
		}
		case GOSSIPSUB_STREAM_VALUE: {
			size_t want = dec->field_len - dec->field_used;
			size_t frame_left = dec->frame_len - dec->frame_used;
			size_t chunk = len - idx;
			if (chunk > want)
				chunk = want;
			if (chunk > frame_left)
				chunk = frame_left;
			if (chunk == 0)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			memcpy(dec->field_buf + dec->field_used, data + idx, chunk);
			dec->field_used += chunk;
			dec->frame_used += chunk;
			idx += chunk;
			if (dec->field_used == dec->field_len)
			{
				libp2p_err_t field_rc = gossipsub_decoder_stream_finish_field(dec);
				if (field_rc != LIBP2P_ERR_OK)
					return field_rc;
			}
			break;
		}
		case GOSSIPSUB_STREAM_SKIP_VARINT: {
			uint8_t byte = data[idx++];
			dec->frame_used++;
			dec->field_header_used++;
			if (dec->field_header_used > sizeof(dec->field_header))
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			if ((byte & 0x80u) == 0)
			{
				dec->field_header_used = 0;
				dec->stream_state = GOSSIPSUB_STREAM_KEY;
			}
			break;
		}
		case GOSSIPSUB_STREAM_SKIP_BYTES: {
			size_t chunk = len - idx;
			size_t frame_left = dec->frame_len - dec->frame_used;
			if (chunk > dec->skip_remaining)
				chunk = dec->skip_remaining;
			if (chunk > frame_left)
				chunk = frame_left;
			if (chunk == 0)
				return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
			idx += chunk;
			dec->frame_used += chunk;
			dec->skip_remaining -= chunk;
			if (dec->skip_remaining == 0)
				dec->stream_state = GOSSIPSUB_STREAM_KEY;
			break;
		}
		default:
			return gossipsub_decoder_fail(dec, LIBP2P_ERR_INTERNAL);
		}

		if (dec->have_length && dec->frame_used == dec->frame_len)
		{
			libp2p_err_t emit_rc = gossipsub_decoder_complete_stream_frame(dec, cb, user_data);
			if (emit_rc != LIBP2P_ERR_OK)
				return emit_rc;
		}
	}

	return LIBP2P_ERR_OK;
}
