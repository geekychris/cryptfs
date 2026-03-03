// SPDX-License-Identifier: GPL-2.0
/*
 * set_key - inject a master key into the CryptoFS kernel module via netlink.
 *
 * Usage: set_key [hex-key]
 *        If no hex-key is given, a random 32-byte key is generated.
 *
 * Build: gcc -o set_key set_key.c -lmnl
 *   (requires libmnl-dev)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <sys/socket.h>

/* ---- mnl-like inline helpers (avoid external dep) ---- */

#define NLMSG_ALIGN(len)  (((len)+3) & ~3)
#define NLA_ALIGN(len)    (((len)+3) & ~3)
#define NLA_HDRLEN        (NLA_ALIGN(sizeof(struct nlattr)))
#define GENL_HDRLEN       NLMSG_ALIGN(sizeof(struct genlmsghdr))

/* Must match kernel/cryptofs.h */
#define CRYPTOFS_GENL_NAME     "cryptofs"
#define CRYPTOFS_GENL_VERSION  1
#define CRYPTOFS_CMD_SET_KEY   4          /* enum cryptofs_nl_commands */
#define CRYPTOFS_ATTR_MASTER_KEY 5        /* enum cryptofs_nl_attrs */
#define CRYPTOFS_KEY_SIZE      32

static int genl_fd;
static uint16_t genl_family_id;
static uint32_t genl_seq;

static int nl_open(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 3 };
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) { perror("socket"); return -1; }
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind"); close(fd); return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/* Resolve the family ID for CRYPTOFS_GENL_NAME */
static int resolve_family(int fd)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct nlattr *nla;
	int len, attrlen;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++genl_seq;

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	/* Add CTRL_ATTR_FAMILY_NAME */
	nla = (struct nlattr *)((char *)genl + GENL_HDRLEN);
	nla->nla_type = CTRL_ATTR_FAMILY_NAME;
	nla->nla_len = NLA_HDRLEN + strlen(CRYPTOFS_GENL_NAME) + 1;
	memcpy((char *)nla + NLA_HDRLEN, CRYPTOFS_GENL_NAME,
	       strlen(CRYPTOFS_GENL_NAME) + 1);
	nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send(ctrl)"); return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) { perror("recv(ctrl)"); return -1; }

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);
		fprintf(stderr, "GETFAMILY error: %d\n", err->error);
		return -1;
	}

	genl = NLMSG_DATA(nlh);
	nla = (struct nlattr *)((char *)genl + GENL_HDRLEN);
	attrlen = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	while (attrlen >= (int)NLA_HDRLEN) {
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
			genl_family_id = *(uint16_t *)((char *)nla + NLA_HDRLEN);
			return 0;
		}
		int step = NLA_ALIGN(nla->nla_len);
		nla = (struct nlattr *)((char *)nla + step);
		attrlen -= step;
	}
	fprintf(stderr, "Could not resolve family ID\n");
	return -1;
}

/* Send CRYPTOFS_CMD_SET_KEY with the given 32-byte key */
static int send_set_key(int fd, const uint8_t *key)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct nlattr *nla;
	int len;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = genl_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++genl_seq;

	genl = NLMSG_DATA(nlh);
	genl->cmd = CRYPTOFS_CMD_SET_KEY;
	genl->version = CRYPTOFS_GENL_VERSION;

	/* Add CRYPTOFS_ATTR_MASTER_KEY */
	nla = (struct nlattr *)((char *)genl + GENL_HDRLEN);
	nla->nla_type = CRYPTOFS_ATTR_MASTER_KEY;
	nla->nla_len = NLA_HDRLEN + CRYPTOFS_KEY_SIZE;
	memcpy((char *)nla + NLA_HDRLEN, key, CRYPTOFS_KEY_SIZE);
	nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send(set_key)"); return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) { perror("recv(set_key)"); return -1; }

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);
		if (err->error != 0) {
			fprintf(stderr, "SET_KEY error: %d\n", err->error);
			return err->error;
		}
	}
	return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, int max)
{
	int len = strlen(hex);
	if (len % 2 != 0 || len / 2 > max) return -1;
	for (int i = 0; i < len / 2; i++) {
		unsigned int v;
		if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return len / 2;
}

int main(int argc, char **argv)
{
	uint8_t key[CRYPTOFS_KEY_SIZE];

	if (argc > 1) {
		if (hex_to_bytes(argv[1], key, CRYPTOFS_KEY_SIZE) != CRYPTOFS_KEY_SIZE) {
			fprintf(stderr, "Bad hex key (need 64 hex chars)\n");
			return 1;
		}
	} else {
		/* Generate a random key */
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0 || read(fd, key, sizeof(key)) != sizeof(key)) {
			perror("urandom"); return 1;
		}
		close(fd);
		printf("Generated random key: ");
		for (int i = 0; i < CRYPTOFS_KEY_SIZE; i++)
			printf("%02x", key[i]);
		printf("\n");
	}

	genl_fd = nl_open();
	if (genl_fd < 0) return 1;

	if (resolve_family(genl_fd) < 0) {
		close(genl_fd); return 1;
	}
	printf("Resolved cryptofs family ID: %u\n", genl_family_id);

	if (send_set_key(genl_fd, key) < 0) {
		close(genl_fd); return 1;
	}

	printf("Key set successfully.\n");
	close(genl_fd);
	return 0;
}
