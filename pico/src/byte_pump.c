#include "pbns_proxy/byte_pump.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static bool buffers_overlap(pbns_buffer left, pbns_buffer right) {
  const uintptr_t left_start = (uintptr_t)left.ptr;
  const uintptr_t right_start = (uintptr_t)right.ptr;
  if (left.cap > UINTPTR_MAX - left_start ||
      right.cap > UINTPTR_MAX - right_start) {
    return true;
  }
  const uintptr_t left_end = left_start + left.cap;
  const uintptr_t right_end = right_start + right.cap;
  return left_start < right_end && right_start < left_end;
}

static bool endpoint_is_valid(pbns_pump_endpoint endpoint) {
  return endpoint.read != NULL && endpoint.write != NULL;
}

static bool status_is_typed(pbns_status status) {
  return status >= PBNS_ERR_BUSY && status <= PBNS_OK;
}

typedef struct pump_direction {
  pbns_byte_ring *ring;
  pbns_pump_endpoint source;
  pbns_pump_endpoint sink;
  bool *source_closed;
  size_t *source_read_generation;
  size_t *sink_write_generation;
  size_t minimum_write;
  size_t minimum_writable;
  bool force_write;
} pump_direction;

static bool should_hold_write(const pump_direction *direction) {
  const size_t size = pbns_byte_ring_size(direction->ring);
  return direction->minimum_write != 0U &&
         size < direction->minimum_write && !direction->force_write &&
         !*direction->source_closed &&
         size < pbns_byte_ring_capacity(direction->ring);
}

static pbns_status write_pending(const pump_direction *direction,
                                 bool *made_progress) {
  pbns_view readable = {0};
  pbns_status status = pbns_byte_ring_readable(direction->ring, &readable);
  if (status != PBNS_OK || readable.len == 0U || should_hold_write(direction)) {
    return status;
  }

  size_t written = 0U;
  status = direction->sink.write(direction->sink.context, readable, &written);
  if (!status_is_typed(status)) {
    return PBNS_ERR_IO;
  }
  if (status == PBNS_ERR_WOULD_BLOCK) {
    return written == 0U ? PBNS_OK : PBNS_ERR_IO;
  }
  if (status != PBNS_OK) {
    return status;
  }
  if (written == 0U || written > readable.len) {
    return PBNS_ERR_IO;
  }
  status = pbns_byte_ring_consume(direction->ring, written);
  if (status == PBNS_OK) {
    if (direction->sink_write_generation != NULL) {
      ++*direction->sink_write_generation;
    }
    *made_progress = true;
  }
  return status;
}

static pbns_status read_available(const pump_direction *direction,
                                  bool *made_progress) {
  if (*direction->source_closed) {
    return PBNS_OK;
  }
  pbns_buffer writable = {0};
  pbns_status status = pbns_byte_ring_writable(direction->ring, &writable);
  if (status != PBNS_OK || writable.cap == 0U) {
    return status;
  }
  if (direction->minimum_writable != 0U &&
      pbns_byte_ring_size(direction->ring) != 0U &&
      writable.cap < direction->minimum_writable) {
    return PBNS_OK;
  }

  size_t received = 0U;
  status =
      direction->source.read(direction->source.context, writable, &received);
  if (!status_is_typed(status)) {
    return PBNS_ERR_IO;
  }
  if (status == PBNS_ERR_WOULD_BLOCK) {
    return received == 0U ? PBNS_OK : PBNS_ERR_IO;
  }
  if (status != PBNS_OK) {
    return status;
  }
  if (received > writable.cap) {
    return PBNS_ERR_IO;
  }
  if (received == 0U) {
    *direction->source_closed = true;
    *made_progress = true;
    return PBNS_OK;
  }
  status = pbns_byte_ring_commit(direction->ring, received);
  if (status == PBNS_OK) {
    if (direction->source_read_generation != NULL) {
      ++*direction->source_read_generation;
    }
    *made_progress = true;
  }
  return status;
}

static pbns_status process_direction(const pump_direction *direction,
                                     bool *made_progress) {
  pbns_status status = write_pending(direction, made_progress);
  if (status != PBNS_OK) {
    return status;
  }
  return read_available(direction, made_progress);
}

static pbns_status fail_pump(pbns_byte_pump *pump, pbns_status status) {
  pump->failed = true;
  return status;
}

void pbns_pump_session_init(pbns_pump_session *session) {
  if (session == NULL) {
    return;
  }
  *session = (pbns_pump_session){
      .initialized = true,
  };
}

pbns_status pbns_pump_session_observe(pbns_pump_session *session,
                                      bool connected, bool *disconnected) {
  if (disconnected != NULL) {
    *disconnected = false;
  }
  if (session == NULL || !session->initialized || disconnected == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *disconnected = session->connected && !connected;
  session->connected = connected;
  return PBNS_OK;
}

void pbns_byte_pump_init(pbns_byte_pump *pump, pbns_buffer usb_to_tls_storage,
                         pbns_buffer tls_to_usb_storage) {
  if (pump == NULL) {
    return;
  }
  *pump = (pbns_byte_pump){0};
  pbns_byte_ring_init(&pump->usb_to_tls, usb_to_tls_storage);
  pbns_byte_ring_init(&pump->tls_to_usb, tls_to_usb_storage);
  if (!pump->usb_to_tls.initialized || !pump->tls_to_usb.initialized ||
      buffers_overlap(usb_to_tls_storage, tls_to_usb_storage)) {
    *pump = (pbns_byte_pump){0};
    return;
  }
  pump->initialized = true;
}

void pbns_byte_pump_reset(pbns_byte_pump *pump) {
  if (pump == NULL || !pump->initialized) {
    return;
  }
  pbns_byte_ring_reset(&pump->usb_to_tls);
  pbns_byte_ring_reset(&pump->tls_to_usb);
  pump->usb_source_closed = false;
  pump->tls_source_closed = false;
  pump->usb_to_tls_read_generation = 0U;
  pump->usb_to_tls_write_generation = 0U;
  pump->cancelled = false;
  pump->failed = false;
}

void pbns_byte_pump_cancel(pbns_byte_pump *pump) {
  if (pump == NULL || !pump->initialized) {
    return;
  }
  pbns_byte_ring_reset(&pump->usb_to_tls);
  pbns_byte_ring_reset(&pump->tls_to_usb);
  pump->cancelled = true;
}

bool pbns_byte_pump_is_complete(const pbns_byte_pump *pump) {
  return pump != NULL && pump->initialized && !pump->cancelled &&
         !pump->failed && pump->usb_source_closed && pump->tls_source_closed &&
         pbns_byte_ring_size(&pump->usb_to_tls) == 0U &&
         pbns_byte_ring_size(&pump->tls_to_usb) == 0U;
}

pbns_status pbns_byte_pump_step_with_policy(
    pbns_byte_pump *pump, pbns_pump_endpoint usb, pbns_pump_endpoint tls,
    const pbns_byte_pump_policy *policy, bool *made_progress) {
  if (made_progress == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *made_progress = false;
  if (pump == NULL || policy == NULL || !endpoint_is_valid(usb) ||
      !endpoint_is_valid(tls)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!pump->initialized || pump->cancelled || pump->failed) {
    return PBNS_ERR_STATE;
  }
  if (pbns_byte_pump_is_complete(pump)) {
    return PBNS_OK;
  }

  const pump_direction usb_to_tls = {
      .ring = &pump->usb_to_tls,
      .source = usb,
      .sink = tls,
      .source_closed = &pump->usb_source_closed,
      .source_read_generation = &pump->usb_to_tls_read_generation,
      .sink_write_generation = &pump->usb_to_tls_write_generation,
      .minimum_write = policy->usb_to_tls_minimum_write,
      .force_write = policy->force_usb_to_tls_write,
  };
  pbns_status status = process_direction(&usb_to_tls, made_progress);
  if (status != PBNS_OK) {
    return fail_pump(pump, status);
  }
  const pump_direction tls_to_usb = {
      .ring = &pump->tls_to_usb,
      .source = tls,
      .sink = usb,
      .source_closed = &pump->tls_source_closed,
      .minimum_writable = policy->tls_to_usb_minimum_writable,
  };
  status = process_direction(&tls_to_usb, made_progress);
  return status == PBNS_OK ? PBNS_OK : fail_pump(pump, status);
}

pbns_status pbns_byte_pump_step(pbns_byte_pump *pump, pbns_pump_endpoint usb,
                                pbns_pump_endpoint tls, bool *made_progress) {
  static const pbns_byte_pump_policy default_policy;
  return pbns_byte_pump_step_with_policy(pump, usb, tls, &default_policy,
                                         made_progress);
}

pbns_status pbns_byte_pump_batch_with_policy(
    pbns_byte_pump *pump, pbns_pump_endpoint usb, pbns_pump_endpoint tls,
    const pbns_byte_pump_policy *policy, size_t *steps,
    bool *made_progress) {
  if (steps != NULL) {
    *steps = 0U;
  }
  if (made_progress != NULL) {
    *made_progress = false;
  }
  if (pump == NULL || policy == NULL || steps == NULL ||
      made_progress == NULL || !endpoint_is_valid(usb) ||
      !endpoint_is_valid(tls)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!pump->initialized || pump->cancelled || pump->failed) {
    return PBNS_ERR_STATE;
  }

  pbns_byte_pump_policy batch_policy = *policy;
  size_t forced_write_generation = pump->usb_to_tls_write_generation;
  for (size_t step_count = 0U;
       step_count < PBNS_BYTE_PUMP_BATCH_MAX_STEPS; ++step_count) {
    bool step_progress = false;
    const pbns_status status = pbns_byte_pump_step_with_policy(
        pump, usb, tls, &batch_policy, &step_progress);
    *steps = step_count + 1U;
    *made_progress = *made_progress || step_progress;
    if (status != PBNS_OK) {
      return status;
    }
    if (batch_policy.force_usb_to_tls_write &&
        pump->usb_to_tls_write_generation != forced_write_generation) {
      batch_policy.force_usb_to_tls_write = false;
    }
    if (!step_progress || pbns_byte_pump_is_complete(pump)) {
      return PBNS_OK;
    }
  }
  return PBNS_OK;
}

pbns_status pbns_byte_pump_batch(pbns_byte_pump *pump, pbns_pump_endpoint usb,
                                 pbns_pump_endpoint tls, size_t *steps,
                                 bool *made_progress) {
  static const pbns_byte_pump_policy default_policy;
  return pbns_byte_pump_batch_with_policy(pump, usb, tls, &default_policy,
                                          steps, made_progress);
}
