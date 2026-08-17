#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/status.h"
#include "pbns_proxy/tcp_write_outcome.h"

static void expect_outcome(pbns_tcp_io_result write_result,
                           pbns_tcp_io_result output_result,
                           size_t queued_bytes, pbns_status expected_status,
                           size_t expected_written) {
  size_t written = SIZE_MAX;
  assert(pbns_tcp_write_outcome(write_result, output_result, queued_bytes,
                                &written) == expected_status);
  assert(written == expected_written);
}

static void test_truth_table(void) {
  expect_outcome(PBNS_TCP_IO_RETRY, PBNS_TCP_IO_NOT_RUN, 17U,
                 PBNS_ERR_WOULD_BLOCK, 0U);
  expect_outcome(PBNS_TCP_IO_FAILED, PBNS_TCP_IO_NOT_RUN, 17U,
                 PBNS_ERR_TRANSPORT, 0U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_OK, 17U, PBNS_OK, 17U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_RETRY, 17U, PBNS_ERR_TRANSPORT,
                 0U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_FAILED, 17U, PBNS_ERR_TRANSPORT,
                 0U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_OK, SIZE_MAX, PBNS_OK, SIZE_MAX);
}

static void test_invalid_arguments_and_combinations(void) {
  expect_outcome(PBNS_TCP_IO_NOT_RUN, PBNS_TCP_IO_NOT_RUN, 17U,
                 PBNS_ERR_ARGUMENT, 0U);
  expect_outcome(PBNS_TCP_IO_NOT_RUN, PBNS_TCP_IO_OK, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_NOT_RUN, PBNS_TCP_IO_RETRY, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_NOT_RUN, PBNS_TCP_IO_FAILED, 17U,
                 PBNS_ERR_ARGUMENT, 0U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_NOT_RUN, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_RETRY, PBNS_TCP_IO_OK, 17U, PBNS_ERR_ARGUMENT, 0U);
  expect_outcome(PBNS_TCP_IO_RETRY, PBNS_TCP_IO_RETRY, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_RETRY, PBNS_TCP_IO_FAILED, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_FAILED, PBNS_TCP_IO_OK, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_FAILED, PBNS_TCP_IO_RETRY, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_FAILED, PBNS_TCP_IO_FAILED, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome((pbns_tcp_io_result)-1, PBNS_TCP_IO_NOT_RUN, 17U,
                 PBNS_ERR_ARGUMENT, 0U);
  expect_outcome((pbns_tcp_io_result)(PBNS_TCP_IO_FAILED + 1),
                 PBNS_TCP_IO_NOT_RUN, 17U, PBNS_ERR_ARGUMENT, 0U);
  expect_outcome(PBNS_TCP_IO_OK, (pbns_tcp_io_result)-1, 17U, PBNS_ERR_ARGUMENT,
                 0U);
  expect_outcome(PBNS_TCP_IO_OK, (pbns_tcp_io_result)(PBNS_TCP_IO_FAILED + 1),
                 17U, PBNS_ERR_ARGUMENT, 0U);
  expect_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_OK, 0U, PBNS_ERR_ARGUMENT, 0U);
  assert(pbns_tcp_write_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_OK, 17U, NULL) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_truth_table();
  test_invalid_arguments_and_combinations();
  return 0;
}
