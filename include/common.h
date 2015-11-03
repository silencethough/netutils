#ifndef PING_H
#define PING_H 1

#include <stdint.h>
#include <sys/capability.h>

static const int warn = 0;
static const int fail = 1;

uint16_t chksum(uint8_t *header, size_t num);
void dropcap(void);
void modifycap(cap_flag_value_t yesorno);

#endif
