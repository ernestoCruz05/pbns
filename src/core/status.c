#include "pbns/status.h"

const char *pbns_status_string(pbns_status status) {
    switch (status) {
        case PBNS_OK:
            return "ok";
        case PBNS_ERR_ARGUMENT:
            return "argument";
        case PBNS_ERR_LIMIT:
            return "limit";
        case PBNS_ERR_FORMAT:
            return "format";
        case PBNS_ERR_CRC:
            return "crc";
        case PBNS_ERR_VERSION:
            return "version";
        case PBNS_ERR_SERVICE:
            return "service";
        case PBNS_ERR_MESSAGE_TYPE:
            return "message-type";
        case PBNS_ERR_SEQUENCE:
            return "sequence";
        case PBNS_ERR_STATE:
            return "state";
        case PBNS_ERR_WOULD_BLOCK:
            return "would-block";
        case PBNS_ERR_TIMEOUT:
            return "timeout";
        case PBNS_ERR_TRANSPORT:
            return "transport";
        case PBNS_ERR_CRYPTO:
            return "crypto";
        case PBNS_ERR_AUTHENTICATION:
            return "authentication";
        case PBNS_ERR_REPLAY:
            return "replay";
        case PBNS_ERR_UNSUPPORTED:
            return "unsupported";
        case PBNS_ERR_UNIMPLEMENTED:
            return "unimplemented";
        case PBNS_ERR_ENTROPY:
            return "entropy";
        case PBNS_ERR_AMBIGUOUS:
            return "ambiguous";
        case PBNS_ERR_RESOURCE:
            return "resource";
        case PBNS_ERR_IO:
            return "io";
        case PBNS_ERR_BUSY:
            return "busy";
        default:
            return "unknown";
    }
}
