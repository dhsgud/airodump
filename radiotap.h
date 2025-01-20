#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <stdint.h>

// Radiotap 헤더 구조체
struct radiotap_header {
    u_int8_t version;
    u_int8_t pad;
    u_int16_t len;
    u_int32_t present;
} __attribute__((__packed__));

#endif // RADIOTAP_H 