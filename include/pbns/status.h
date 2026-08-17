#ifndef PBNS_STATUS_H
#define PBNS_STATUS_H

typedef enum pbns_status {
    PBNS_OK = 0,
    PBNS_ERR_ARGUMENT = -1,
    PBNS_ERR_LIMIT = -2,
    PBNS_ERR_FORMAT = -3,
    PBNS_ERR_CRC = -4,
    PBNS_ERR_VERSION = -5,
    PBNS_ERR_SERVICE = -6,
    PBNS_ERR_MESSAGE_TYPE = -7,
    PBNS_ERR_SEQUENCE = -8,
    PBNS_ERR_STATE = -9,
    PBNS_ERR_WOULD_BLOCK = -10,
    PBNS_ERR_TIMEOUT = -11,
    PBNS_ERR_TRANSPORT = -12,
    PBNS_ERR_CRYPTO = -13,
    PBNS_ERR_AUTHENTICATION = -14,
    PBNS_ERR_REPLAY = -15,
    PBNS_ERR_UNSUPPORTED = -16,
    PBNS_ERR_UNIMPLEMENTED = -17,
    PBNS_ERR_ENTROPY = -18,
    PBNS_ERR_AMBIGUOUS = -19,
    PBNS_ERR_RESOURCE = -20,
    PBNS_ERR_IO = -21,
    PBNS_ERR_BUSY = -22
} pbns_status;

const char *pbns_status_string(pbns_status status);

#endif
