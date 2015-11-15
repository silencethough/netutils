#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

uint16_t chksum(uint8_t *header, size_t length)
{
	uint8_t *index = header;
	uint16_t value = 0, result;
	uint32_t sum = 0;
	size_t num = length;

	while (num >= 2) {
		memcpy(&value, index, sizeof(uint16_t));
		index += 2;
		sum += value;
		num -= 2;
	}

	if (num == 1)
		sum += *index;

	/* RFC1071 */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum;

	/* little endian */
	memcpy(&result, &sum, sizeof(uint16_t));

	return result;
}
