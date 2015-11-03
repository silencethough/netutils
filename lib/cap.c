#include <sys/capability.h>
#include <stdlib.h>
#include <errno.h>
#include <error.h>
#include "common.h"

void dropcap(void)
{
	cap_t caps;

	caps = cap_init();
	if (!caps)
		error(fail, errno, "cap_init");

	if (cap_set_proc(caps) == -1) {
		cap_free(caps);
		error(fail, errno, "cap_set_proc");
	}
}

void modifycap(cap_flag_value_t yesorno)
{
	cap_t caps;
	cap_value_t cap_list[1] = {CAP_NET_RAW};

	caps = cap_get_proc();
	if(!caps)
		error(fail, errno, "cap_get_proc");

	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, yesorno) != 0) {
		cap_free(caps);
		error(fail, errno, "cap_set_flag");
	}

	if (cap_set_proc(caps) != 0) {
		cap_free(caps);
		error(fail, errno, "cap_set_proc");
	}

	cap_free(caps);
}
