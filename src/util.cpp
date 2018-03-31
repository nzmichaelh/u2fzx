#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "u2f"
#include <logging/sys_log.h>

#include <misc/__assert.h>
#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include "util.h"

#include "sfs.h"

void u2f_took(const char *msg, int *start)
{
	u32_t now = k_uptime_get_32();
	s32_t took = now - *start;
	*start = now;

	printk("%d (+%d) %s\n", now, took, msg);
}

void u2f_dump_hex(const char *msg, const u8_t *buf, int len)
{
	printk("%u %s(%d): ", k_uptime_get_32(), msg, len);
	for (int i = 0; i < len; i++) {
		printk(" %x", buf[i]);
	}
	printk("\n");
}

void u2f_dump_hex(const char *msg, const gtl::span<u8_t> &s)
{
	u2f_dump_hex(msg, s.cbegin(), s.size());
}
