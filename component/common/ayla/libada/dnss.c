/*
 * Copyright 2011-2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/tlv.h>
#include <ayla/endian.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/dns.h>
#include <ayla/conf.h>
#include <ayla/clock.h>
#include <ayla/random.h>
#include <ayla/timer.h>
#include <net/net.h>
#include <net/ipaddr_fmt.h>
#include <net/ada_mbuf.h>
#include <ada/dnss.h>
#include <ada/server_req.h>
#include "client_timer.h"
#include "dnss_internal.h"
#ifdef MFI
#include "../../bci/mfi/mfi.h"
#include "../../bci/mfi/hap.h"
#endif /* MFI */

#define DNSS_TTL	10	/* seconds time-to-live for responses */
#define DNSS_QNAME_LEN  128	/* query name buf len */
#define DNSS_TXT_TTL	4500	/* TTL for SRV/TXT records in MDNS responses */
#define DNSS_A_TTL	120	/* TTL for A/AAAA records in MDNS responses */
#define DNSS_MAX_RSP	512	/* max size of the response */
#define DNSS_MAX_MDNS_TIME	(60 * 60)	/* max time mdns is on */
#define DNSS_MDNS_RAND_DLY	100	/* delay should be 20ms-120ms */
#define DNSS_MDNS_RAND_DLY_MIN	20
#define DNSS_PROBE_INTLV	500	/* 500ms between successive probes */
#define DNSS_PROBE_CONFLICT_TIME (5 * 1000)	/* RFC: 6762: 8.1: 5 sec */

#define IPADDR_MULTICAST    ((u32_t)0xfb0000e0UL) /* v4 link local mcast addr */

#ifdef DNSS_IPV6
static const ipX_addr_t mdns_mcast_ip = {
	.ip4 = { IPADDR_MULTICAST }
};
static const ipX_addr_t mdns_mcast_ipv6 = {
	.ip6 = { { PP_HTONL(0xff020000), 0, 0, PP_HTONL(0xfb) } } /* ff02::fb */
};
#else
static const ipX_addr_t mdns_mcast_ip = { IPADDR_MULTICAST };
#endif /* DNSS_IPV6 */

#define DNSS_SD_NAME	"_services._dns-sd._udp.local."
static const char dnss_sd_name[] = DNSS_SD_NAME;

/*
 * Forward declarations
 */
struct dnss_rsp_state;
struct dns_rr_hdr;

#if defined(MFI) || defined(HOMEKIT)
static const char mfi_srv_name[] = MFI_SERVICE_NAME;
static int dnss_rsp_append_mfidata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u16 class, u32 ttl);
static int dnss_cmp_mfi_rr(struct ada_mbuf *, struct dns_rr_hdr *rr, u16 type);

#if defined(HOMEKIT)
static const char hap_srv_name[] = HAP_SERVICE_NAME;
static int dnss_rsp_append_hapdata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u16 class, u32 ttl);
static int dnss_cmp_hap_rr(struct ada_mbuf *, struct dns_rr_hdr *rr, u16 type);
#endif
#endif

#if defined(MFI) || defined(HOMEKIT)
static const struct {
	const char *name;
	int (*rsp_f)(struct dnss_rsp_state *rstate, const char *name, u16 type,
	    u16 class, u32 ttl);
	int (*cmp_f)(struct ada_mbuf *, struct dns_rr_hdr *rr, u16 type);
} srv_info[] = {
	{ mfi_srv_name, dnss_rsp_append_mfidata, dnss_cmp_mfi_rr },
#if defined(HOMEKIT)
	{ hap_srv_name, dnss_rsp_append_hapdata, dnss_cmp_hap_rr }
#endif
};
#endif

#if defined(MFI) && defined(HOMEKIT)
#define DNSS_SRV_CNT		2
#elif defined(MFI)
#define DNSS_SRV_CNT		1
#endif

#define DNSS_SRV_ENABLED(idx)	((1 << (idx)) & dnss_state.mdns_adv)

struct dnss_req_q_elem {
	u16 name_off;
	u16 off;
	int gen_rsp;
};

struct dnss_req_elem {
	u16 name_off;
	u16 off;
};

#define DNSS_REQ_Q_CNT		3
#define DNSS_REQ_RR_CNT		8

struct dnss_rsp_state {
	struct netif *nif;		/* itf where the req came in */
	struct ada_mbuf *resp;		/* response buf */
	int resp_off;			/* offset in response */
#if defined(HOMEKIT)
	enum dnss_req_response {
		A_RSP = 0x1,
		AAAA_RSP = 0x2,
		SRV_RSP = 0x4,
		TXT_RSP = 0x8,
		PTR_RSP = 0x10,
		SD_PTR_RSP = 0x20,
	} resp_mdns[DNSS_SRV_CNT];
#endif
	u16 xid;			/* response id */
	u16 flags;			/* response flags */
	u8 is_v6:1;			/* v6 response */
	u8 mcast_resp:1;		/* multicast response */
	u8 legacy_resp:1;		/* legacy request */
	ipX_addr_t dst_addr;
};

struct dnss_req_state {
	struct ada_mbuf *req;
	struct dnss_req_q_elem qry[DNSS_REQ_Q_CNT];
	struct dnss_req_elem rr[DNSS_REQ_RR_CNT];
	u16 off;		/* offset in request */
	u8 host_match:1;	/* req has our hostname in queries */
	u8 srv_match:2;		/* req has service name in queries */
	u8 shared_resp:1;	/* delay response by 20-120 ms */
	u8 respond:1;		/* whether we should respond or not */
	struct dnss_rsp_state *rsp;
};

PREPACKED struct dns_qry_hdr {
	be16 type;		/* RR type code */
	be16 class;		/* RR class */
} PACKED;

#define DNS_Q_HDR(p, off) \
		((struct dns_qry_hdr *)&((char *)ada_mbuf_payload(p))[off])

PREPACKED struct dns_rr_hdr {
	be16 type;		/* RR type code */
	be16 class;		/* RR class */
	be32 ttl;		/* time to live, seconds */
	be16 rdlength;		/* resource data length */
} PACKED;

#define DNS_RR_HDR(p, off) \
		((struct dns_rr_hdr *)&((char *)ada_mbuf_payload(p))[off])

PREPACKED struct dns_srv_rr {
	struct dns_rr_hdr hdr;
	be16 priority;		/* priority */
	be16 weight;		/* server selection */
	be16 port;		/* portnumber */
	u8 rdata[0];
} PACKED;

/*
 * DNS query/response structure
 */
struct dnss_parse_res {
	u16 name_off;
	u16 off;
};

struct dnss_state dnss_state;

#if defined(MFI) || defined(HOMEKIT)
/*
 * This is for state of belated response.
 */
static struct dnss_rsp_state dnss_dly_rsp;
static int dnss_dly_rsp_set;

static void dnss_mdns_tmo(struct timer *);
#endif

#if defined(MFI) || defined(HOMEKIT)
/*
 * Response should be multicasted out.
 */
#ifdef DNSS_IPV6
static void dnss_mcast_rsp(struct dnss_rsp_state *rstate)
{
	if (rstate->is_v6) {
		ipX_addr_copy(rstate->is_v6, rstate->dst_addr,
		    mdns_mcast_ipv6);
	} else {
		ipX_addr_copy(rstate->is_v6, rstate->dst_addr,
		    mdns_mcast_ip);
	}
}
#else /* DNSS_IPV6 */
static void dnss_mcast_rsp(struct dnss_rsp_state *rstate)
{
	ipX_addr_copy(rstate->is_v6, rstate->dst_addr, mdns_mcast_ip);
}
#endif /* DNSS_IPV6 */

static void *dnss_add_qry_record(u8 *bp, int *offp, const char *name,
    u16 type, u16 class)
{
	struct dns_qry_hdr *qry;
	int off = *offp;

	if (strlen(name) + 1 + off + sizeof(struct dns_qry_hdr) >
	    DNSS_MAX_RSP) {
		return NULL;
	}

	off += dnss_fill_name(bp, name, &bp[off]);
	qry = (struct dns_qry_hdr *)&bp[off];
	put_ua_be16(&qry->type, type);
	put_ua_be16(&qry->class, class);
	off += sizeof(*qry);
	*offp = off;

	return qry;
}
#endif /* MFI || HOMEKIT */

static int dnss_append_rr(u8 *bp, int *offp, const char *name,
    u16 type, u16 class, u32 ttl, void *data, int dlen)
{
	struct dns_rr_hdr *rr;
	struct dns_srv_rr *srv;
	int off = *offp;

	off += dnss_fill_name(bp, name, &bp[off]);
	rr = (struct dns_rr_hdr *)&bp[off];
	put_ua_be16(&rr->type, type);
	put_ua_be16(&rr->class, class);
	put_ua_be32(&rr->ttl, ttl);

	switch (type) {
	case DNS_RRTYPE_PTR:
		dlen = dnss_fill_name(bp, data, rr + 1);
		break;
	case DNS_RRTYPE_SRV:
		srv = (struct dns_srv_rr *)rr;
		srv->priority = 0;
		srv->weight = 0;
		srv->port = htons(HTTPD_PORT);
		dlen = dnss_fill_name(bp, data, srv + 1);
		dlen += sizeof(*srv) - sizeof(*rr);
		break;
	default:
		memcpy(rr + 1, data, dlen);
		break;
	}
	off += dlen + sizeof(*rr);
	put_ua_be16(&rr->rdlength, dlen);
	*offp = off;

	return 0;
}

static int dnss_rsp_append_mydata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u16 class, u32 ttl)
{
	ip_addr_t *v4addr;
#ifdef DNSS_IPV6
	ip6_addr_t *v6addr;
#endif
	u8 *bp = ada_mbuf_payload(rstate->resp);

	switch (type) {
	case DNS_RRTYPE_A:
		v4addr = dnss_my_v4addr(rstate->nif);
		return dnss_append_rr(bp, &rstate->resp_off, name, DNS_RRTYPE_A,
		    class, ttl, v4addr, sizeof(*v4addr));
#ifdef DNSS_IPV6
	case DNS_RRTYPE_AAAA:
		v6addr = dnss_my_v6addr(rstate->nif);
		return dnss_append_rr(bp, &rstate->resp_off, name,
		    DNS_RRTYPE_AAAA, class, ttl, v6addr, sizeof(*v6addr));
#endif /* DNSS_IPV6 */
	default:
		return -1;
	}
}

#if defined(MFI) || defined(HOMEKIT)
static int dnss_rsp_append_mfidata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u16 class, u32 ttl)
{
	char tmp_str[192];
	int tmp_str_len;
	u8 *bp = ada_mbuf_payload(rstate->resp);

	switch (type) {
	case DNS_RRTYPE_TXT:
		tmp_str_len = mfi_create_dns_txt(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_SRV:
		tmp_str_len = dnss_device_name(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_PTR:
		tmp_str_len = dnss_service_name(tmp_str, sizeof(tmp_str),
		    mfi_srv_name);
		break;
	default:
		return -1;
	}
	return dnss_append_rr(bp, &rstate->resp_off, name, type, class, ttl,
	    tmp_str, tmp_str_len);
}

#if defined(HOMEKIT)
static int dnss_rsp_append_hapdata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u16 class, u32 ttl)
{
	char tmp_str[192];
	int tmp_str_len;
	u8 *bp = ada_mbuf_payload(rstate->resp);

	switch (type) {
	case DNS_RRTYPE_TXT:
		tmp_str_len = hap_create_dns_txt(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_SRV:
		tmp_str_len = dnss_device_name(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_PTR:
		tmp_str_len = dnss_service_name(tmp_str, sizeof(tmp_str),
		    hap_srv_name);
		break;
	default:
		return -1;
	}
	return dnss_append_rr(bp, &rstate->resp_off, name, type, class, ttl,
	    tmp_str, tmp_str_len);
}
#endif

static int dnss_rsp_append_sddata(struct dnss_rsp_state *rstate,
    const char *name, u16 type, u32 ttl, int srv_idx)
{
	u8 *bp = ada_mbuf_payload(rstate->resp);

	if (type == DNS_RRTYPE_PTR) {
		return dnss_append_rr(bp, &rstate->resp_off, name, type,
		    DNS_RRCLASS_IN, ttl, (char *)srv_info[srv_idx].name,
		    strlen(srv_info[srv_idx].name));
	} else {
		return -1;
	}
}
#endif /* MFI || HOMEKIT */

/*
 * Parse DNS query/response packets
 */
static enum dns_rcode dnss_parse(struct dnss_req_state *rstate,
    struct dnss_parse_res *dnss_entry)
{
	u8 *bp = ada_mbuf_payload(rstate->req);
	size_t len = ada_mbuf_len(rstate->req);
	size_t tlen;

	dnss_entry->name_off = rstate->off;
	for (dnss_entry->off = rstate->off; dnss_entry->off < len;
	    dnss_entry->off += tlen) {
		tlen = bp[dnss_entry->off++];
		if (tlen == 0) {
			goto tail;
		}

		/*
		 * Handle pointer.
		 */
		if (tlen > DNSL_MASK) {
			if (dnss_entry->off >= len) {
				return DNSR_ERR_FMT;
			}
			if ((tlen & DNSL_PTR) != DNSL_PTR) {
				return DNSR_ERR_FMT;
			}
			tlen = (tlen & DNSL_MASK << 8) | bp[dnss_entry->off++];
			goto tail;
		}
	}
	return DNSR_ERR_FMT;		/* no null termination */

tail:
	if (dnss_entry->off + 2 * sizeof(be16) > len) {
		return DNSR_ERR_FMT;
	}
	return DNSR_OK;
}

static int dnss_req_parse(struct dnss_req_state *rstate)
{
	struct dnss_parse_res dpr;
	struct dns_head *hdr = ada_mbuf_payload(rstate->req);
	int i;
	int cnt;
	int rc;
	struct dns_rr_hdr *rr;

	cnt = hdr->qdcount;
	for (i = 0; i < cnt; i++) {
		rc = dnss_parse(rstate, &dpr);
		if (rc) {
			return rc;
		}
		if (i >= DNSS_REQ_Q_CNT) {
			continue;
		}
		rstate->qry[i].name_off = dpr.name_off;
		rstate->qry[i].off = dpr.off;
		rstate->qry[i].gen_rsp = 0;
		rstate->off = dpr.off + sizeof(struct dns_qry_hdr);
	}
	cnt = hdr->ancount + hdr->nscount + hdr->arcount;
	for (i = 0; i < cnt; i++) {
		rc = dnss_parse(rstate, &dpr);
		if (rc) {
			return rc;
		}
		if (i >= DNSS_REQ_RR_CNT) {
			continue;
		}
		rstate->rr[i].name_off = dpr.name_off;
		rstate->rr[i].off = dpr.off;
		rr = DNS_RR_HDR(rstate->req, dpr.off);
		rstate->off = dpr.off + sizeof(struct dns_rr_hdr) +
		    get_ua_be16(&rr->rdlength);
	}
	return 0;
}

/*
 * Call (*func) for every query record
 */
static int dnss_req_foreach_q(struct dnss_req_state *rstate,
    int (*func)(struct dnss_req_state *, struct dnss_req_q_elem *elem,
	void *arg),
    void *cb_arg)
{
	int i;
	int rc;
	int cnt;
	struct dns_head *hdr = ada_mbuf_payload(rstate->req);
	struct dnss_req_q_elem *qelem = rstate->qry;

	cnt = hdr->qdcount;
	if (cnt > DNSS_REQ_Q_CNT) {
		cnt = DNSS_REQ_Q_CNT;
	}
	for (i = 0; i < cnt; i++) {
		rc = func(rstate, &qelem[i], cb_arg);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

#if defined(MFI) || defined(HOMEKIT)
/*
 * Call (*func) for every resource record
 */
static int dnss_req_foreach_rr(struct dnss_req_state *rstate,
    int (*func)(struct dnss_req_state *, struct dnss_req_elem *elem, void *arg),
    void *cb_arg)
{
	int i;
	int rc;
	int cnt;
	struct dns_head *hdr = ada_mbuf_payload(rstate->req);
	struct dnss_req_elem *elem = rstate->rr;

	cnt = hdr->ancount + hdr->nscount + hdr->arcount;
	if (cnt > DNSS_REQ_RR_CNT) {
		cnt = DNSS_REQ_RR_CNT;
	}
	for (i = 0; i < cnt; i++) {
		rc = func(rstate, &elem[i], cb_arg);
		if (rc) {
			return rc;
		}
	}
	return 0;
}
#endif /* MFI || HOMEKIT */

static int dns_cb_dns_qry(struct dnss_req_state *rstate,
    struct dnss_req_q_elem *elem, void *arg)
{
	struct ada_mbuf *req = rstate->req;
	struct ada_mbuf *rsp = rstate->rsp->resp;
	struct dns_qry_hdr *qry;
	struct dns_head *hdr;
	char hostname[DNSS_QNAME_LEN];

	qry = DNS_Q_HDR(req, elem->off);
	if (get_ua_be16(&qry->type) == DNS_RRTYPE_A) {
		/*
		 * Respond.
		 */
		if (dnss_copy_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), hostname, sizeof(hostname)) < 0) {
			return DNSR_ERR_FMT;
		}
		if (dnss_rsp_append_mydata(rstate->rsp, hostname, DNS_RRTYPE_A,
		    DNS_RRCLASS_IN, DNSS_TTL)) {
			return DNSR_ERR_SERVER;
		}
		hdr = ada_mbuf_payload(rsp);
		hdr->ancount++;
		elem->gen_rsp = 1;
		rstate->respond = 1;
	}
	return 0;
}

static int dns_cb_disc_qry(struct dnss_req_state *rstate,
    struct dnss_req_q_elem *elem, void *arg)
{
	struct ada_mbuf *req = rstate->req;
	struct ada_mbuf *rsp = rstate->rsp->resp;
	struct dns_qry_hdr *qry;
	struct dns_head *hdr;
	char hostname[DNSS_QNAME_LEN];

	snprintf(hostname, sizeof(hostname), "%s.local.", conf_sys_dev_id);

	qry = DNS_Q_HDR(req, elem->off);
	if (get_ua_be16(&qry->type) == DNS_RRTYPE_A &&
	    !dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), hostname)) {
		/*
		 * Respond.
		 */
		if (dnss_rsp_append_mydata(rstate->rsp, hostname, DNS_RRTYPE_A,
			DNS_RRCLASS_IN, DNSS_TTL)) {
			return DNSR_ERR_SERVER;
		}
		hdr = ada_mbuf_payload(rsp);
		hdr->ancount++;
		elem->gen_rsp = 1;

		rstate->respond = 1;

		dnss_log(LOG_DEBUG "rx host mdns query");
	}
	return 0;
}

#if defined(MFI) || defined(HOMEKIT)
static int dns_cb_mdns_qry(struct dnss_req_state *rstate,
    struct dnss_req_q_elem *elem, void *arg)
{
	struct ada_mbuf *req = rstate->req;
	struct dnss_rsp_state *rsp = rstate->rsp;
	struct dns_qry_hdr *qry;
	u16 type;
	u16 class;
	char name[DNSS_QNAME_LEN];
	int i;

	qry = DNS_Q_HDR(req, elem->off);
	type = get_ua_be16(&qry->type);
	class = get_ua_be16(&qry->class);

	if (!(class & DNS_RRCLASS_QU)) {
		rstate->rsp->mcast_resp = 1;
	}

#ifdef DNSS_DEBUG
	if (dnss_copy_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), name, sizeof(name)) < 0) {
		strcpy(name, "?");
	}
	dnss_log(LOG_DEBUG "mdns query type 0x%x %s \"%s\"",
	    type, (class & DNS_RRCLASS_QU) ? "QU" : "QM", name);
#endif /* DNSS_DEBUG */

	dnss_device_name(name, sizeof(name));
	if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), name)) {
		switch (type) {
		case DNS_QTYPE_ANY:
			rsp->resp_mdns[0] |= A_RSP | AAAA_RSP;
			elem->gen_rsp = 1;
			break;
		case DNS_RRTYPE_A:
			rsp->resp_mdns[0] |= A_RSP;
			rstate->host_match = 1;
			elem->gen_rsp = 1;
			break;
		case DNS_RRTYPE_AAAA:
			rsp->resp_mdns[0] |= AAAA_RSP;
			rstate->host_match = 1;
			elem->gen_rsp = 1;
			break;
		default:
			rstate->host_match = 1;
			break;
		}
	}
	if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), dnss_sd_name)) {
		if (type == DNS_RRTYPE_PTR || type == DNS_QTYPE_ANY) {
			for (i = 0; i < DNSS_SRV_CNT; i++) {
				if (!DNSS_SRV_ENABLED(i)) {
					continue;
				}
				rsp->resp_mdns[i] |= SD_PTR_RSP;
				rstate->shared_resp = 1;
				elem->gen_rsp = 1;
			}
		}
	}
	for (i = 0; i < DNSS_SRV_CNT; i++) {
		if (!DNSS_SRV_ENABLED(i)) {
			continue;
		}
		/*
		 * We only respond to queries about one service at a time.
		 */
		dnss_service_name(name, sizeof(name), srv_info[i].name);
		if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), name)) {
			switch (type) {
			case DNS_QTYPE_ANY:
				rsp->resp_mdns[i] |=
				    SRV_RSP | TXT_RSP | A_RSP | AAAA_RSP;
				elem->gen_rsp = 1;
				break;
			case DNS_RRTYPE_SRV:
				rsp->resp_mdns[i] |= SRV_RSP;
				rstate->srv_match |= (1 << i);
				elem->gen_rsp = 1;
				break;
			case DNS_RRTYPE_TXT:
				rsp->resp_mdns[i] |= TXT_RSP;
				rstate->srv_match |= (1 << i);
				elem->gen_rsp = 1;
				break;
			default:
				rstate->srv_match |= (1 << i);
				break;
			}
		}
		if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), srv_info[i].name)) {
			if (type == DNS_RRTYPE_PTR || type == DNS_QTYPE_ANY) {
				rsp->resp_mdns[i] |= PTR_RSP;
				rstate->shared_resp = 1;
				elem->gen_rsp = 1;
			}
		}
	}

	return 0;
}

static int dns_mdns_resp(struct dnss_rsp_state *rstate)
{
	struct ada_mbuf *rsp = rstate->resp;
	struct dns_head *hdr = ada_mbuf_payload(rsp);
	u32 ttl;
	char name[DNSS_QNAME_LEN];
	int i;
	u16 class;

	if (rstate->mcast_resp && !rstate->legacy_resp) {
		dnss_mcast_rsp(rstate);
	}
	if (!rstate->legacy_resp) {
		class = DNS_RRCLASS_IN | DNS_RRCLASS_FLUSH;
		ttl = 0;
	} else {
		/*
		 * Legacy request must not have the flush bit.
		 * And RRs must come with short TTL.
		 */
		class = DNS_RRCLASS_IN;
		ttl = DNSS_A_TTL;
	}
	for (i = 0; i < DNSS_SRV_CNT; i++) {
		dnss_service_name(name, sizeof(name), srv_info[i].name);
		if (rstate->resp_mdns[i] & SD_PTR_RSP) {
			if (dnss_rsp_append_sddata(rstate, dnss_sd_name,
				DNS_RRTYPE_PTR, ttl ? ttl : DNSS_TXT_TTL, i)) {
				return -1;
			}
			hdr->ancount++;
		}
		if (rstate->resp_mdns[i] & PTR_RSP) {
			if (srv_info[i].rsp_f(rstate, srv_info[i].name,
				DNS_RRTYPE_PTR, DNS_RRCLASS_IN,
				ttl ? ttl : DNSS_TXT_TTL)) {
				return -1;
			}
			hdr->ancount++;
			rstate->resp_mdns[i] |= SRV_RSP | TXT_RSP;
			rstate->resp_mdns[0] |= A_RSP | AAAA_RSP;
		}
		if (rstate->resp_mdns[i] & SRV_RSP) {
			if (srv_info[i].rsp_f(rstate, name, DNS_RRTYPE_SRV,
				class, ttl ? ttl : DNSS_TXT_TTL)) {
				return -1;
			}
			hdr->ancount++;
			rstate->resp_mdns[0] |= A_RSP | AAAA_RSP;
		}
		if (rstate->resp_mdns[i] & TXT_RSP) {
			if (srv_info[i].rsp_f(rstate, name, DNS_RRTYPE_TXT,
				class, ttl ? ttl : DNSS_TXT_TTL)) {
				return -1;
			}
			hdr->ancount++;
		}
	}
	dnss_device_name(name, sizeof(name));
	if (rstate->resp_mdns[0] & A_RSP) {
		if (dnss_rsp_append_mydata(rstate, name, DNS_RRTYPE_A,
			class, DNSS_A_TTL)) {
			return -1;
		}
		hdr->ancount++;
	}
#ifdef DNSS_IPV6
	if (rstate->resp_mdns[0] & AAAA_RSP) {
		if (dnss_rsp_append_mydata(rstate, name, DNS_RRTYPE_AAAA,
			class, DNSS_A_TTL)) {
			return -1;
		}
		hdr->ancount++;
	}
#endif
	return hdr->ancount;
}

/*
 * Add rr offsets in order. Compare first record class (without cache flush
 * bit), then type.
 */
static void dnss_add_rr(struct dnss_req_state *rstate,
    u16 off_arr[DNSS_REQ_RR_CNT], int *off_cnt, u16 new_off)
{
	u8 *bp = ada_mbuf_payload(rstate->req);
	int i;
	struct dns_qry_hdr *new, *old;
	u16 nclass;
	u16 oclass;

	new = (struct dns_qry_hdr *)&bp[new_off];
	nclass = ntohs(new->class) & ~DNS_RRCLASS_FLUSH;

	for (i = 0; i < *off_cnt; i++) {
		old = (struct dns_qry_hdr *)&bp[off_arr[i]];
		oclass = ntohs(old->class) & ~DNS_RRCLASS_FLUSH;

		if (nclass < oclass ||
		    (nclass == oclass && ntohs(new->type) < ntohs(old->type))) {
			break;
		}
	}
	if (i < DNSS_REQ_RR_CNT) {
		memcpy(&off_arr[i + 1], &off_arr[i],
		    sizeof(off_arr[0]) * (DNSS_REQ_RR_CNT - 1 - i));
		off_arr[i] = new_off;
	}
	if (*off_cnt < DNSS_REQ_RR_CNT) {
		*off_cnt += 1;
	}
}

static int dnss_cmp_rr(struct ada_mbuf *p, struct dns_rr_hdr *rr, u16 class,
    u16 type, void *data, int dlen)
{
	struct dns_srv_rr *srv;
	struct dns_srv_rr srv_cmp;
	int rc;
	int tmp;
	u16 rdlength;

	rdlength = get_ua_be16(&rr->rdlength);
#ifdef DNSS_DEBUG
	dnss_log(LOG_DEBUG "cmp_rr class %d type %d ttl %u len %d",
	    get_ua_be16(&rr->class), get_ua_be16(&rr->type),
	    get_ua_be32(&rr->ttl), rdlength));
#endif
	rc = (get_ua_be16(&rr->class) & ~DNS_RRCLASS_FLUSH) - class;
	if (rc) {
		return rc;
	}
	rc = get_ua_be16(&rr->type) - type;
	if (rc) {
		return rc;
	}
	switch (type) {
	case DNS_RRTYPE_A:
		if (rdlength != sizeof(struct ip_addr)) {
			/*
			 * Invalid record, we win.
			 */
			return 1;
		}
		rc = memcmp(rr + 1, data, sizeof(struct ip_addr));
		return rc;
#ifdef DNSS_IPV6
	case DNS_RRTYPE_AAAA:
		if (rdlength != sizeof(struct ip6_addr)) {
			/*
			 * Invalid record, we win.
			 */
			return 1;
		}
		rc = memcmp(rr + 1, data, sizeof(struct ip6_addr));
		return rc;
#endif
	case DNS_RRTYPE_TXT:
		tmp = rdlength;
		if (tmp > dlen) {
			tmp = dlen;
		}
		rc = memcmp(rr + 1, data, tmp);
		if (!rc) {
			rc = rdlength - dlen;
		}
		return rc;
	case DNS_RRTYPE_SRV:
		if (rdlength + 2 < sizeof(*srv)) {
			/*
			 * Invalid record.
			 */
			return 1;
		}
		srv = (struct dns_srv_rr *)rr;
		memset(&srv_cmp, 0, sizeof(srv_cmp));
		srv_cmp.port = htons(HTTPD_PORT);
		rc = memcmp(&srv->priority, &srv_cmp.priority,
		    sizeof(*srv) - sizeof(*rr));
		if (rc) {
			break;
		}
		rc = dnss_cmp_name(ada_mbuf_payload(p),
		    (u8 *)(srv + 1) - (u8 *)ada_mbuf_payload(p),
		    ada_mbuf_len(p), data);
#ifdef DNSS_DEBUG
		dnss_log(LOG_DEBUG "cmp_srv rc %d for %s", rc, (char *)data);
#endif
		break;
	case DNS_RRTYPE_PTR:
		rc = dnss_cmp_name(ada_mbuf_payload(p),
		    (u8 *)(rr + 1) - (u8 *)ada_mbuf_payload(p),
		    ada_mbuf_len(p), data);
#ifdef DNSS_DEBUG
		dnss_log(LOG_DEBUG "cmp_ptr rc %d for %s", rc, (char *)data);
#endif
		break;
	default:
		/*
		 * Unknown record, ignore it by saying that we're winner.
		 */
		return 1;
	}
	return rc;
}

/*
 * Match RR contents to our data.
 */
static int dnss_cmp_mydata_rr(struct ada_mbuf *p, struct dns_rr_hdr *rr,
				u16 type)
{
	struct netif *nif;
	void *data;
	int dlen;

	nif = ada_mbuf_netif(p);
	switch (type) {
	case DNS_RRTYPE_A:
		data = dnss_my_v4addr(nif);
		dlen = sizeof(struct ip_addr);
		break;
#ifdef DNSS_IPV6
	case DNS_RRTYPE_AAAA:
		data = dnss_my_v6addr(nif);
		dlen = sizeof(struct ip6_addr);
		break;
#endif
	default:
		return -1;
	}
	return dnss_cmp_rr(p, rr, DNS_RRCLASS_IN, type, data, dlen);
}

static int dnss_cmp_mfi_rr(struct ada_mbuf *p, struct dns_rr_hdr *rr, u16 type)
{
	char tmp_str[192];
	int tmp_str_len;

	switch (type) {
	case DNS_RRTYPE_TXT:
		tmp_str_len = mfi_create_dns_txt(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_SRV:
		tmp_str_len = dnss_device_name(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_PTR:
		tmp_str_len = dnss_service_name(tmp_str, sizeof(tmp_str),
		    mfi_srv_name);
		break;
	default:
		return -1;
	}
	return dnss_cmp_rr(p, rr, DNS_RRCLASS_IN, type, tmp_str, tmp_str_len);
}

#if defined(HOMEKIT)
static int dnss_cmp_hap_rr(struct ada_mbuf *p, struct dns_rr_hdr *rr, u16 type)
{
	char tmp_str[192];
	int tmp_str_len;

	switch (type) {
	case DNS_RRTYPE_TXT:
		tmp_str_len = hap_create_dns_txt(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_SRV:
		tmp_str_len = dnss_device_name(tmp_str, sizeof(tmp_str));
		break;
	case DNS_RRTYPE_PTR:
		tmp_str_len = dnss_service_name(tmp_str, sizeof(tmp_str),
		    hap_srv_name);
		break;
	default:
		return -1;
	}
	return dnss_cmp_rr(p, rr, DNS_RRCLASS_IN, type, tmp_str, tmp_str_len);
}
#endif

static int dnss_cmp_sddata_rr(struct ada_mbuf *p, struct dns_rr_hdr *rr,
				u16 type,
    int srv_idx)
{
	void *data;

	if (type != DNS_RRTYPE_PTR) {
		return -1;
	}
	data = (void *)srv_info[srv_idx].name;
	return dnss_cmp_rr(p, rr, DNS_RRCLASS_IN, type, data, 0);
}

/*
 * We have one DNS_RRCLASS_IN + DNS_RRTYPE_A and
 * DNS_RRCLASS_IN + DNS_RRTYPE_AAAA.
 * A is numerically lower than AAAA, so it is matched first.
 */
static int dnss_cmp_name_rr(struct dnss_req_state *rstate, u16 offs[3],
    int off_cnt)
{
	u8 *bp = ada_mbuf_payload(rstate->req);
	struct dns_rr_hdr *rr;
	int rc;

	if (!off_cnt) {
		/*
		 * We have records. We win.
		 */
		return 1;
	}

	rr = (struct dns_rr_hdr *)&bp[offs[0]];
	rc = dnss_cmp_mydata_rr(rstate->req, rr, DNS_RRTYPE_A);
	if (rc) {
		return rc;
	}
	if (off_cnt < 2) {
		return 1;
	}

	rr = (struct dns_rr_hdr *)&bp[offs[1]];
	rc = dnss_cmp_mydata_rr(rstate->req, rr, DNS_RRTYPE_AAAA);
	if (rc) {
		return rc;
	}

	if (off_cnt == 3) {
		/*
		 * Data identical, but they have more records. They win.
		 */
		return -1;
	}
	return 0;
}

/*
 * We have one DNS_RRCLASS_IN + DNS_RRTYPE_TXT and
 * DNS_RRCLASS_IN + DNS_RRTYPE_SRV.
 */
static int dnss_cmp_srv_rr(struct dnss_req_state *rstate, u16 offs[3],
    int off_cnt, int srv_idx)
{
	u8 *bp = ada_mbuf_payload(rstate->req);
	struct dns_rr_hdr *rr;
	int rc;

	if (!off_cnt) {
		/*
		 * We have records. We win.
		 */
		return 1;
	}

	rr = (struct dns_rr_hdr *)&bp[offs[0]];
	rc = srv_info[srv_idx].cmp_f(rstate->req, rr, DNS_RRTYPE_TXT);
	if (rc) {
		return rc;
	}

	if (off_cnt < 2) {
		return 1;
	}

	rr = (struct dns_rr_hdr *)&bp[offs[1]];
	rc = srv_info[srv_idx].cmp_f(rstate->req, rr, DNS_RRTYPE_SRV);
	if (rc) {
		return rc;
	}
	if (off_cnt == 3) {
		/*
		 * Data identical, but they have more records. They win.
		 */
		return -1;
	}
	return 0;
}

struct dns_probe_cb_rr_arg {
	char *name;
	u16 rr_arr[DNSS_REQ_RR_CNT];
	int rr_cnt;
};

static int dnss_probe_cb_rr_order(struct dnss_req_state *rstate,
    struct dnss_req_elem *elem, void *arg)
{
	struct ada_mbuf *req = rstate->req;
	struct dns_probe_cb_rr_arg *cb_arg = (struct dns_probe_cb_rr_arg *)arg;

	if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), cb_arg->name)) {
		dnss_add_rr(rstate, cb_arg->rr_arr, &cb_arg->rr_cnt, elem->off);
	}
	return 0;
}

/*
 * Handles mdns probe conflicts
 */
static enum dns_rcode dnss_probe_conflict(struct dnss_req_state *rstate)
{
	struct dns_head *hdr;
	char name[DNSS_QNAME_LEN];
	int is_announcement;
	int rc;
	int i;
	int conflict = 0;
	struct dns_probe_cb_rr_arg rr_arg;

	hdr = ada_mbuf_payload(rstate->req);

	if (hdr->nscount) {
		is_announcement = 0;
	} else {
		is_announcement = 1;
	}

	/*
	 * Compare first record class (without cache flush bit),
	 * then type, then binary content of the record.
	 *
	 * If we lose, we wait for 1 second, and restart probing.
	 * The winner (if present), should then take ownership of
	 * this name and reject our subsequent probes.
	 */
	if (rstate->host_match) {
		conflict |= 1;
		dnss_device_name(name, sizeof(name));
		rr_arg.name = name;
		rr_arg.rr_cnt = 0;

		rc = dnss_req_foreach_rr(rstate, dnss_probe_cb_rr_order,
		    &rr_arg);
		if (rc) {
			return DNSR_ERR_FMT;
		}

		/*
		 * Hostname conflicts.
		 */
		rc = dnss_cmp_name_rr(rstate, rr_arg.rr_arr, rr_arg.rr_cnt);
		if (rc > 0) {
			dnss_log(LOG_DEBUG "we lose");
		} else {
			if (!rc || !is_announcement) {
				dnss_log(LOG_DEBUG "we win");
				conflict &= ~1;
			}
		}
	}

	for (i = 0; i < DNSS_SRV_CNT; i++) {
		if (!DNSS_SRV_ENABLED(i)) {
			continue;
		}
		if (!(rstate->srv_match & (1 << i))) {
			continue;
		}
		conflict |= 2;
		dnss_service_name(name, sizeof(name), srv_info[i].name);
		rr_arg.name = name;
		rr_arg.rr_cnt = 0;

		rc = dnss_req_foreach_rr(rstate, dnss_probe_cb_rr_order,
		    &rr_arg);
		if (rc) {
			return DNSR_ERR_FMT;
		}

		/*
		 * Service name conflicts.
		 */
		rc = dnss_cmp_srv_rr(rstate, rr_arg.rr_arr, rr_arg.rr_cnt, i);
		if (rc > 0) {
			dnss_log(LOG_DEBUG "we lose");
		} else {
			if (!rc || !is_announcement) {
				dnss_log(LOG_DEBUG "we win");
				conflict &= ~2;
			}
		}
	}
	if (conflict) {
#ifdef DNSS_DEBUG
		dnss_log(LOG_DEBUG "has conflict %d", conflict);
#endif /* DNSS_DEBUG */
		dnss_state.mdns_state = MDNS_PROBE1;
		if (is_announcement) {
			client_timer_set(&state->adv_timer, 1);
		} else {
			client_timer_set(&state->adv_timer, 1000);
		}
	}
	return DNSR_OK;
}

/*
 * Match mDNS answer RRs against our data.
 */
struct dns_cb_match_arg {
	enum dnss_req_response match[DNSS_SRV_CNT];
	enum dnss_req_response diff[DNSS_SRV_CNT];
};

static int dnss_mdns_response_match(struct dnss_req_state *rstate,
    struct dnss_req_elem *elem, void *arg)
{
	struct ada_mbuf *req = rstate->req;
	struct dns_rr_hdr *rr;
	u16 class;
	u16 type;
	u32 ttl;
	struct dns_cb_match_arg *cb_arg = (struct dns_cb_match_arg *)arg;
	char name[DNSS_QNAME_LEN];
	enum dnss_req_response match;
	int i;

	rr = DNS_RR_HDR(req, elem->off);
	class = get_ua_be16(&rr->class) & ~DNS_RRCLASS_FLUSH;
	type = get_ua_be16(&rr->type);
	ttl = get_ua_be32(&rr->ttl);

	dnss_device_name(name, sizeof(name));
	if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), name)) {
		switch (type) {
		case DNS_RRTYPE_A:
			match = A_RSP;
			break;
		case DNS_RRTYPE_AAAA:
			match = AAAA_RSP;
			break;
		default:
			/*
			 * Unknown RRs. Marking these as different makes
			 * us pick a different name.
			 */
			cb_arg->diff[0] |= A_RSP | AAAA_RSP;
			return 0;
		}
		if (class == DNS_RRCLASS_IN &&
		    !dnss_cmp_mydata_rr(req, rr, type)) {
			if (ttl > DNSS_A_TTL / 2) {
				cb_arg->match[0] = match;
			}
		} else {
			cb_arg->diff[0] = match;
		}
		return 0;
	}
	for (i = 0; i < DNSS_SRV_CNT; i++) {
		if (!DNSS_SRV_ENABLED(i)) {
			continue;
		}
		dnss_service_name(name, sizeof(name), srv_info[i].name);
		if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), name)) {
			switch (type) {
			case DNS_RRTYPE_SRV:
				match = SRV_RSP;
				break;
			case DNS_RRTYPE_TXT:
				match = TXT_RSP;
				break;
			default:
				cb_arg->diff[i] |= SRV_RSP | TXT_RSP;
				return 0;
			}
			if (class == DNS_RRCLASS_IN &&
			    !srv_info[i].cmp_f(req, rr, type)) {
				if (ttl > DNSS_TXT_TTL / 2) {
					cb_arg->match[i] = match;
				}
			} else {
				cb_arg->diff[i] = match;
			}
			return 0;
		}

		/*
		 * For PTR records we only look for matching RRs.
		 */
		if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), srv_info[i].name)) {
			if (type == DNS_RRTYPE_PTR && class == DNS_RRCLASS_IN &&
			    !srv_info[i].cmp_f(req, rr, type)) {
				if (ttl > DNSS_TXT_TTL / 2) {
					cb_arg->match[i] |= PTR_RSP;
				}
			}
			return 0;
		}
		if (!dnss_cmp_name(ada_mbuf_payload(req), elem->name_off,
		    ada_mbuf_len(req), dnss_sd_name)) {
			if (type == DNS_RRTYPE_PTR && class == DNS_RRCLASS_IN &&
			    !dnss_cmp_sddata_rr(req, rr, type, i)) {
				if (ttl > DNSS_TXT_TTL / 2) {
					cb_arg->match[i] |= SD_PTR_RSP;
				}
			}
			return 0;
		}
	}
	return 0;
}

/*
 * Duplicate answer supression. If we'd answer for shared records, but
 * querier already lists this element, then don't respond.
 */
static void dnss_mdns_supress_dup_rsp(struct dnss_req_state *rstate)
{
	struct dnss_rsp_state *rsp;
	struct dns_cb_match_arg cb_arg;
	int i;

	rsp = rstate->rsp;
	memset(&cb_arg, 0, sizeof(cb_arg));

	dnss_req_foreach_rr(rstate, dnss_mdns_response_match, &cb_arg);
	for (i = 0; i < DNSS_SRV_CNT; i++) {
		rsp->resp_mdns[i] &= ~cb_arg.match[i];
		dnss_dly_rsp.resp_mdns[i] &= ~cb_arg.match[i];
	}
}

static void dnss_response(struct dnss_req_state *rstate)
{
	struct dnss_state *state = &dnss_state;
	struct dnss_rsp_state *rsp;
	struct dns_cb_match_arg cb_arg;
	int i;
	int conflict_type = 0;

	rsp = rstate->rsp;
	memset(&cb_arg, 0, sizeof(cb_arg));

	dnss_req_foreach_rr(rstate, dnss_mdns_response_match, &cb_arg);
	for (i = 0; i < DNSS_SRV_CNT; i++) {
		rsp->resp_mdns[i] &= ~cb_arg.match[i];
		dnss_dly_rsp.resp_mdns[i] &= ~cb_arg.match[i];
		if (cb_arg.diff[i] & (SRV_RSP | TXT_RSP)) {
			conflict_type |= 2;
		}
	}
	if (cb_arg.diff[0] & (A_RSP | AAAA_RSP)) {
		conflict_type |= 1;
	}

#ifdef DNSS_DEBUG
	if (conflict_type) {
		dnss_log(LOG_DEBUG "recv: mDNS conflict %d while in %d",
		    conflict_type, state->mdns_state);
	}
#endif /* DNSS_DEBUG */
	if (!conflict_type) {
		return;
	}
/*
 * RFC 6762: 9: Conflict Resolution
 */
	if (state->mdns_state > MDNS_ADV_FAST1) {
		/*
		 * This hostname belongs to us, probe again
		 * without changing it.
		 */
		state->mdns_state = MDNS_PROBE1;
		client_timer_set(&state->adv_timer, 1);
	} else if ((state->mdns_state <= MDNS_ADV_FAST1) &&
	    (state->mdns_state >= MDNS_PROBE1)) {
		/*
		 * This hostname belongs to someone else, change it.
		 * NOTE: mdns_state increments before probe is sent
		 * out and so probe 3 is sent after state is advanced
		 * to MDNS_ADV_FAST1
		 */
		if (conflict_type & 1) {
			dnss_state.mdns_hname_suf++;
		}
		if (conflict_type & 2) {
			dnss_state.mdns_sname_suf++;
		}
		state->mdns_state = MDNS_PROBE1;
		client_timer_set(&state->adv_timer, DNSS_PROBE_CONFLICT_TIME);
	}
}

/*
 * Copy query records that generated response.
 */
static int dns_cb_mdns_copy_qry(struct dnss_req_state *rstate,
    struct dnss_req_q_elem *elem, void *arg)
{
	struct dnss_rsp_state *rsp;
	struct ada_mbuf *req = rstate->req;
	struct ada_mbuf *p;
	struct dns_qry_hdr *qry;
	char name[DNSS_QNAME_LEN];
	struct dns_head *hdr;

	if (!elem->gen_rsp) {
		return 0;
	}
	rsp = rstate->rsp;
	p = rsp->resp;
	hdr = ada_mbuf_payload(p);

	qry = DNS_Q_HDR(req, elem->off);
	if (dnss_copy_name(ada_mbuf_payload(req), elem->name_off,
	    ada_mbuf_len(req), name, sizeof(name)) < 0) {
		return DNSR_ERR_FMT;
	}
	qry = dnss_add_qry_record(ada_mbuf_payload(p), &rsp->resp_off, name,
	    get_ua_be16(&qry->type), get_ua_be16(&qry->class));
	if (!qry) {
		return DNSR_ERR_SERVER;
	}
	hdr->qdcount++;

	return 0;
}

static int dnss_tx_mdns_rsp(struct dnss_rsp_state *rstate)
{
	struct ada_mbuf *resp;
	struct dns_head *head;
	char host_str[46];
	int rc;

	resp = ada_mbuf_alloc(DNSS_MAX_RSP);
	if (!resp) {
		rc = ERR_MEM;
		goto drop;
	}
	head = ada_mbuf_payload(resp);
	memset(head, 0, sizeof(*head));
	rstate->resp = resp;
	rstate->resp_off = sizeof(*head);

	rc = dns_mdns_resp(rstate);
	if (rc == 0) {
		goto drop;
	} else if (rc < 0) {
		rc = ERR_VAL;
		goto drop;
	}
	ada_mbuf_trim(resp, rstate->resp_off);

	head->id = rstate->xid;
	head->flags = rstate->flags;
	head->ancount = htons(head->ancount);

	ip_addr_ntop(rstate->is_v6, &rstate->dst_addr, host_str,
	    sizeof(host_str));
	dnss_log(LOG_DEBUG "dlyd DNS response %d bytes to %s",
	    ada_mbuf_len(resp), host_str);
	rc = net_udp_sendto_if(dnss_state.mdns_pcb,
	    resp, ipX_2_ip(&rstate->dst_addr), MDNS_PORT,
	    rstate->nif ? rstate->nif : netif_default);
drop:
	ada_mbuf_free(resp);
	if (rc) {
		dnss_log(LOG_WARN "DNS dlyd rsp fail: %d", rc);
	}
	return rc;
}

static void dnss_mdns_rsp_tmo(struct timer *timer)
{
	client_timer_cancel(timer);
	dnss_tx_mdns_rsp(&dnss_dly_rsp);
	dnss_dly_rsp_set = 0;
}

static void dnss_recv_mdns(struct dnss_req_state *rstate)
{
	struct dns_head *hdr = ada_mbuf_payload(rstate->req);
	struct dnss_rsp_state *rsp = rstate->rsp;
	u8 dly;
	int i;

	if (hdr->qdcount) {
		dnss_req_foreach_q(rstate, dns_cb_mdns_qry, NULL);
		if (hdr->nscount) {
			/* check for probe conflict */
			dnss_probe_conflict(rstate);
		}
		if (dnss_state.mdns_state <= MDNS_ADV_FAST1) {
			/*
			 * Don't respond to queries if we're still probing
			 */
			return;
		}
		if (hdr->ancount || hdr->arcount) {
			dnss_mdns_supress_dup_rsp(rstate);
		}
		if (rsp->mcast_resp && rstate->shared_resp &&
		    !rsp->legacy_resp) {
			/*
			 * Responding in mcast to a query that has possibly
			 * others responders. Delay sending the response.
			 */
			if (dnss_dly_rsp_set) {
				/*
				 * Already one pending. Answer prev question
				 * now. Scrub from 2nd response RRs that we're
				 * sending now.
				 */
				for (i = 0; i < DNSS_SRV_CNT; i++) {
					rsp->resp_mdns[i] &=
					    ~dnss_dly_rsp.resp_mdns[i];
				}
				dnss_mdns_rsp_tmo(&dnss_state.rsp_timer);
			}
			dnss_dly_rsp = *rsp;
			dnss_dly_rsp_set = 1;
			random_fill(&dly, 1);
			dly = (dly % DNSS_MDNS_RAND_DLY) +
			    DNSS_MDNS_RAND_DLY_MIN;
			client_timer_set(&state->rsp_timer, dly);
		} else {
			if (rsp->legacy_resp) {
				/*
				 * For these we have to copy in query as well.
				 */
				dnss_req_foreach_q(rstate, dns_cb_mdns_copy_qry,
				    NULL);
			}
			if (dns_mdns_resp(rsp) > 0) {
				rstate->respond = 1;
			}
		}
	} else if (hdr->ancount || hdr->arcount) {
		/*
		 * This may be a reply to contest our probe
		 * or someone else may have incorrect records
		 */
		dnss_response(rstate);
	}
}
#endif /* MFI || HOMEKIT */

static void dnss_recv_dns(struct dnss_req_state *rstate)
{
	dnss_req_foreach_q(rstate, dns_cb_dns_qry, NULL);
}

static void dnss_recv_disc(struct dnss_req_state *rstate)
{
	dnss_req_foreach_q(rstate, dns_cb_disc_qry, NULL);
}

/*
 * Handles dnss messages.
 * src_port is the port the sender sent the message from.
 * dest_port (defined inside the function) is our bind port.
 */
static void dnss_recv(void *arg, struct net_udp *pcb, struct ada_mbuf *req,
		ip_addr_t *addr, u16_t src_port)
{
	struct dnss_req_state req_state;
	struct dnss_rsp_state rsp_state;
	struct dns_head *head;
	struct dns_head *rhead;
	struct ada_mbuf *resp = NULL;
	struct ada_mbuf *new_req;
	enum dns_rcode rcode = DNSR_OK;
	u16 flags;
	enum ada_err err;
	u16 dest_port = (u16)(u32)arg;
	char host_str[46];

	if (!req) {
		return;
	}
	new_req = ada_mbuf_coalesce(req);
	if (!new_req) {
		dnss_log(LOG_ERR "recv: coalesce failed");
		goto drop;
	}
	req = new_req;
	if (ada_mbuf_len(req) < sizeof(*head)) {
		dnss_log(LOG_WARN "recv: len %u too short", ada_mbuf_len(req));
		goto drop;
	}
	head = ada_mbuf_payload(req);
	flags = ntohs(head->flags);

	/*
	 * Set up the req state structure
	 */
	req_state.req = req;
	req_state.off = sizeof(*head);
	req_state.host_match = 0;
	req_state.srv_match = 0;
	req_state.shared_resp = 0;
	req_state.respond = 0;
	req_state.rsp = &rsp_state;

	memset(&rsp_state, 0, sizeof(rsp_state));
	rsp_state.nif = ada_mbuf_netif(req);
	rsp_state.is_v6 = net_udp_is_v6(pcb);
	rsp_state.xid = head->id;
	ipX_addr_set(rsp_state.is_v6, &rsp_state.dst_addr, ip_2_ipX(addr));

	if (dest_port == MDNS_PORT_DISC) {
		rsp_state.flags =
		    htons(DNSF_RSP | (DNSQ_IQUERY << (DNSF_OP_BIT - 1)));
	} else {
		rsp_state.flags = htons(DNSF_RSP | (DNSQ_QUERY << DNSF_OP_BIT));
	}

	/*
	 * Allocate response and clear its payload.
	 */
	resp = ada_mbuf_alloc(DNSS_MAX_RSP);
	if (!resp) {
		rcode = DNSR_ERR_SERVER;
		goto drop;
	}
	rhead = ada_mbuf_payload(resp);
	memset(rhead, 0, sizeof(struct dns_head));
	rsp_state.resp = resp;
	rsp_state.resp_off = sizeof(*head);

	head->qdcount = ntohs(head->qdcount);
	head->ancount = ntohs(head->ancount);
	head->nscount = ntohs(head->nscount);
	head->arcount = ntohs(head->arcount);

	rcode = dnss_req_parse(&req_state);
	if (rcode) {
		goto drop_resp;
	}
	switch (dest_port) {
	case DNSS_PORT:
		if (rcode || flags & DNSF_RSP) {
			rcode = DNSR_ERR_FMT;
			goto error;
		}

		/*
		 * Respond to any A query with our address.
		 */
		dnss_recv_dns(&req_state);
		break;
	case MDNS_PORT_DISC:
		/*
		 * Respond to queries for our name with our address.
		 */
		dnss_recv_disc(&req_state);
		break;
#if defined(MFI) || defined(HOMEKIT)
	case MDNS_PORT:
		/*
		 * Respond to queries for our name or services.
		 */
		if (src_port != MDNS_PORT) {
			rsp_state.legacy_resp = 1;
		}
		dnss_recv_mdns(&req_state);
		break;
#endif
	default:
		break;
	}

	if (!req_state.respond) {
		goto drop_resp;
	}
	ada_mbuf_trim(resp, rsp_state.resp_off);

	/*
	 * Set up response header.
	 */
	rhead->flags = rsp_state.flags;

	/*
	 * Send response.
	 */
send:
	rhead->id = rsp_state.xid;
	rhead->qdcount = htons(rhead->qdcount);
	rhead->ancount = htons(rhead->ancount);
	rhead->nscount = htons(rhead->nscount);
	rhead->arcount = htons(rhead->arcount);

	ip_addr_ntop(rsp_state.is_v6, &rsp_state.dst_addr, host_str,
	    sizeof(host_str));
	dnss_log(LOG_DEBUG "sending DNS response %d bytes to %s",
	    ada_mbuf_len(resp), host_str);

	err = net_udp_sendto_if(pcb, resp, ipX_2_ip(&rsp_state.dst_addr),
	    src_port, ada_mbuf_netif(req));
	if (err != AE_OK) {
		/*
		 * With MFI and IPv6, this might fail. This when we've
		 * just activated STA interface, and we're still doing DAD
		 * on the link local address. If we haven't validated
		 * our tentative address yet, we shouldn't use it as a source
		 * address. Address validation takes 1-2 secs.
		 */
		dnss_log(LOG_ERR "recv: send err %d", err);
	}
drop_resp:
	ada_mbuf_free(resp);
drop:
	ada_mbuf_free(req);
	return;

error:
	if (!resp) {
		goto drop;
	}
	dnss_log(LOG_DEBUG "recv: replying rcode %x", rcode);
	rhead->flags = htons(DNSF_RSP | (DNSQ_QUERY << DNSF_OP_BIT) | rcode);
	rhead->ancount = 0;
	ada_mbuf_trim(resp, sizeof(*rhead));
	goto send;
}

#if defined(MFI) || defined(HOMEKIT)
/*
 * Probe Query/Advertisment for MFI/HAP service
 */
static enum dns_rcode dnss_announce(struct dnss_rsp_state *rstate, int srv_idx,
    u16 qclass, int set_ttl)
{
	struct ada_mbuf *reply;
	struct dns_head *head;
	struct dns_rr_hdr *rr;
	char name[DNSS_QNAME_LEN];
	int rr_cnt = 0;
	u16 qclass1;

	/*
	 * Send a probe mDNS query to check if the resource records are
	 * already in use on the local network.
	 * RFC 6762: 8.1.
	 *	query type: ANY
	 *	RRCLASS: IN
	 *	Probes to be sent with QU bit set
	 * RFC 6762: 8.2.
	 *	Populate Authority section with the rdata
	 *
	 * Send mDNS announcement after probe
	 * RFC 6762: 8.3.
	 *	All records in Answer Section
	 *	RRCLASS: Cache Flush bit set
	 */
	reply = rstate->resp;
	head = ada_mbuf_payload(reply);

	if (dnss_state.mdns_state <= MDNS_ADV_FAST1) { /* Probe */
		qclass1 = qclass;
		if (dnss_state.mdns_state == MDNS_PROBE2) {
			qclass1 |= DNS_RRCLASS_QU;
		}
		dnss_device_name(name, sizeof(name));
		rr = dnss_add_qry_record(ada_mbuf_payload(reply),
		    &rstate->resp_off, name, DNS_QTYPE_ANY, qclass1);
		if (!rr) {
			return DNSR_ERR_SERVER;
		}
		dnss_service_name(name, sizeof(name), srv_info[srv_idx].name);
		/* One question each for IP records and SRV/TXT records */
		rr = dnss_add_qry_record(ada_mbuf_payload(reply),
		    &rstate->resp_off,
		    name, DNS_QTYPE_ANY, qclass1);
		if (!rr) {
			return DNSR_ERR_SERVER;
		}
	} else { /* Announce */
		/*
		 * PTR record
		 */
		if (dnss_rsp_append_sddata(rstate, dnss_sd_name, DNS_RRTYPE_PTR,
			set_ttl ? DNSS_TXT_TTL : 0, srv_idx)) {
			return DNSR_ERR_SERVER;
		}
		/*
		 * PTR record
		 */
		if (srv_info[srv_idx].rsp_f(rstate, srv_info[srv_idx].name,
			DNS_RRTYPE_PTR, qclass, set_ttl ? DNSS_TXT_TTL : 0)) {
			return DNSR_ERR_SERVER;
		}

		/*
		 * Set Cache Flush Bit for all other records
		 */
		qclass |= DNS_RRCLASS_FLUSH;
		rr_cnt += 2;
	}

	/*
	 * SRV record
	 */
	dnss_service_name(name, sizeof(name), srv_info[srv_idx].name);
	if (srv_info[srv_idx].rsp_f(rstate, name, DNS_RRTYPE_SRV, qclass,
		set_ttl ? DNSS_TXT_TTL : 0)) {
		return DNSR_ERR_SERVER;
	}
	/*
	 * Next the TXT record
	 */
	if (srv_info[srv_idx].rsp_f(rstate, name, DNS_RRTYPE_TXT, qclass,
		set_ttl ? DNSS_TXT_TTL : 0)) {
		return DNSR_ERR_SERVER;
	}

	/*
	 * Finally the address records.
	 */
	dnss_device_name(name, sizeof(name));
	if (dnss_rsp_append_mydata(rstate, name, DNS_RRTYPE_A, qclass,
		set_ttl ? DNSS_A_TTL : 0)) {
		return DNSR_ERR_SERVER;
	}
	rr_cnt += 3;
#ifdef DNSS_IPV6
	if (dnss_rsp_append_mydata(rstate, name, DNS_RRTYPE_AAAA, qclass,
		set_ttl ? DNSS_A_TTL : 0)) {
		return DNSR_ERR_SERVER;
	}
	rr_cnt++;
#endif /* DNSS_IPV6 */


	if (dnss_state.mdns_state <= MDNS_ADV_FAST1) { /* Probe */
		head->nscount = htons(rr_cnt);
		head->qdcount = htons(2);
	} else { /* Announce */
		head->ancount = htons(rr_cnt);
	}
	return DNSR_OK;
}

/*
 * Advertise MFI service
 */
static void dnss_mdns_advertise(void)
{
	struct dnss_rsp_state rstate;
	struct dns_head *head;
	struct ada_mbuf *resp;
#ifdef DNSS_IPV6
	struct ada_mbuf *p;
#endif
	int set_ttl;
	int rc;
	int i;

	for (i = 0; i < DNSS_SRV_CNT; i++) {
		set_ttl = 1;
		if (DNSS_SRV_ENABLED(i)) {
			if ((1 << i) & dnss_state.mdns_adv_bye) {
				/*
				 * TTL 0 tells others that service is
				 * ending on this node.
				 */
				set_ttl = 0;
			}
		} else { /* Do not adv this srv */
			continue;
		}

		memset(&rstate, 0, sizeof(rstate));
		resp = ada_mbuf_alloc(DNSS_MAX_RSP);
		if (!resp) {
			rc = AE_BUF;
			goto drop_resp;
		}
		head = ada_mbuf_payload(resp);
		memset(head, 0, sizeof(*head));
		rstate.resp = resp;
		rstate.resp_off = sizeof(*head);

		rc = dnss_announce(&rstate, i, DNS_RRCLASS_IN, set_ttl);
		if (rc != DNSR_OK) {
			rc = ERR_INVAL_STATE;
			goto drop_resp;
		}
		ada_mbuf_trim(resp, rstate.resp_off);

		if (dnss_state.mdns_state <= MDNS_ADV_FAST1) { /* Probe */
			head->flags = htons(DNSF_QRY |
			    (DNSQ_QUERY << DNSF_OP_BIT));
		} else { /* Announce */
			head->flags = htons(DNSF_RSP | DNSF_AA |
			    (DNSQ_QUERY << DNSF_OP_BIT));
		}
#ifdef DNSS_IPV6
		/*
		 * Make a copy of the contents. We cannot use the same buf,
		 * even if we have to free it here.
		 */
		p = ada_mbuf_alloc(ada_mbuf_len(res));
		if (p) {
			rc = ada_mbuf_copy(p, resp);
			ASSERT(rc == AE_OK);
		}
#endif /* DNSS_IPV6 */
		dnss_log(LOG_DEBUG "tx DNS %s for %s",
		    dnss_state.mdns_state <= MDNS_ADV_FAST1 ?
		    "probe" : "announce", srv_info[i].name);
		rc = udp_sendto_if(dnss_state.mdns_pcb, resp,
		    (ip_addr_t *)&mdns_mcast_ip, MDNS_PORT, netif_default);
#ifdef DNSS_IPV6
		if (p) {
			udp_sendto_if_ip6(dnss_state.mdns_pcb_v6, p,
			    &mdns_mcast_ipv6, MDNS_PORT, netif_default);
			ada_mbuf_free(p);
		}
#endif /* DNSS_IPV6 */
drop_resp:
		ada_mbuf_free(resp);
		if (rc) {
			dnss_log(LOG_WARN "DNS advertisement fail: %d", rc);
		}
	}
}

static void dnss_mdns_tmo(void *arg)
{
	struct dnss_state *state = (struct dnss_state *)arg;
	int tmo, send = 0;
	struct clock_time ct;
	s16 time;

	if (state->mdns_state <= MDNS_PROBE3) {
		tmo = DNSS_PROBE_INTLV; /* should be 250ms according to spec */
		state->mdns_state++;
		send = 1;
	} else if (state->mdns_state <= MDNS_ADV_FAST2) {
		tmo = 2000;
		state->mdns_state++;
		send = 1;
	} else {
		tmo = (DNSS_A_TTL - (DNSS_A_TTL / 10)) * 1000;
	}

	clock_get(&ct);
	time = ct.ct_sec;
	if ((((s16)time - (s16)state->mdns_start_time) > DNSS_MAX_MDNS_TIME) &&
	    (state->mdns_adv & DNSS_ADV_MFI)) {
		/*
		 * Failsafe in case iOS configuring device abandons us
		 * before completing final config step.
		 */
		dnss_mdns_stop(DNSS_ADV_MFI, 1);
	}
	if (send) {
		dnss_mdns_advertise();
	}
	/* Continue to adv srv which are set to adv */
	if (state->mdns_adv) {
		client_timer_set(&state->adv_timer, tmo);
	}
}
#endif /* MFI || HOMEKIT */

/*
 * dnss_up - start DNS service.
 */
static struct net_udp *dnss_up_helper(ip_addr_t *bind_addr, u16 bind_port,
    int v6)
{
	struct net_udp *pcb;
	enum ada_err err;
#if defined(MFI) || defined(HOMEKIT)
	struct dnss_state *state = &dnss_state;

	if (!timer_initialized(&state->rsp_timer)) {
		timer_init(&state->rsp_timer, dnss_mdns_rsp_tmo);
		timer_init(&state->adv_timer, dnss_mdns_tmo);
	}
#endif /* MFI || HOMEKIT */
	pcb = net_udp_new();
	if (!pcb) {
		dnss_log(LOG_ERR "dnss_up: udp_new failed");
		return NULL;
	}
#ifdef DNSS_IPV6
	net_udp_set_v6(pcb, v6);
#endif /* DNSS_IPV6 */
	err = net_udp_bind(pcb, bind_addr, bind_port);
	if (err != AE_OK) {
		dnss_log(LOG_ERR "dnss_up: UDP bind err %d", err);
		goto error;
	}
	net_udp_recv(pcb, dnss_recv, (void *)(u32)bind_port);

	return pcb;
error:
	net_udp_remove(pcb);
	return NULL;
}

static struct net_udp *dnss_up_mcast_helper(ip_addr_t *ifaddr,
    ip_addr_t *bind_addr, u16 bind_port)
{
	enum ada_err err;
	struct net_udp *pcb;

	pcb = dnss_up_helper(bind_addr, bind_port, 0);
	if (!pcb) {
		return NULL;
	}
	err = net_igmp_joingroup(pcb, ifaddr, (ip_addr_t *)&mdns_mcast_ip);
	if (err != AE_OK) {
		net_udp_remove(pcb);
		dnss_log(LOG_WARN "failed to join multicast group");
		return NULL;
	}
	return pcb;
}

#if defined(DNSS_IPV6) && (defined(MFI) || defined(HOMEKIT))
static struct net_udp *dnss_up_v6mcast_helper(struct ip6_addr *ifaddr,
    struct ip6_addr *bind_addr, u16 bind_port)
{
	enum ada_err err;

	err = mld6_joingroup(ifaddr, (ip6_addr_t *)&mdns_mcast_ipv6);
	if (err == AE_OK) {
		return dnss_up_helper(ip6_2_ip(bind_addr), bind_port, 1);
	} else {
		dnss_log(LOG_WARN "failed to join v6 mcast group");
		return NULL;
	}
}
#endif /* DNSS_IPV6 && (MFI || HOMEKIT) */

static void dnss_close_helper(struct net_udp **pcb)
{
	if (*pcb) {
		net_udp_remove(*pcb);
		*pcb = NULL;
	}
}

void dnss_up(void)
{
	struct dnss_state *state = &dnss_state;

	if (state->pcb) {
		return;
	}
	state->pcb = dnss_up_helper(IPADDR_ANY, DNSS_PORT, 0);
}

void dnss_down(void)
{
	struct dnss_state *state = &dnss_state;

	dnss_close_helper(&state->pcb);
}

/*
 * dnss_mdns_disc_up - start MDNS service.
 */
void dnss_mdns_disc_up(struct netif *nif)
{
	struct dnss_state *state = &dnss_state;
	struct net_udp *pcb;
	ip_addr_t *ifaddr;

	if (state->mdns_disc_pcb) {
		return;
	}
	ifaddr = dnss_my_v4addr(nif);
	pcb = dnss_up_mcast_helper(ifaddr, NULL, MDNS_PORT_DISC);
	state->mdns_disc_pcb = pcb;
}

void dnss_mdns_disc_down(void)
{
	struct dnss_state *state = &dnss_state;

	dnss_close_helper(&state->mdns_disc_pcb);
}

#if defined(MFI) || defined(HOMEKIT)
/*
 * Start advertising _mfi-config as service. Advertising is only done
 * for an hour.
 */
void dnss_mdns_start(u8 adv_mask)
{
	struct dnss_state *state = &dnss_state;
	struct net_udp *pcb;

	/*
	 * We should respond to multicast requests only when they come
	 * from local net. If the request comes to 224.0.0.251, that is
	 * enough of a check. XXX should add that
	 */
	if (!state->mdns_adv) {
		state->mdns_hname_suf = 0;

		if (!state->mdns_pcb) {
			pcb = dnss_up_mcast_helper(IPADDR_ANY, NULL, MDNS_PORT);
			state->mdns_pcb = pcb;
		}
#ifdef DNSS_IPV6
		if (!state->mdns_pcb_v6) {
			pcb = dnss_up_v6mcast_helper(IP6_ADDR_ANY, NULL,
			    MDNS_PORT);
			state->mdns_pcb_v6 = pcb;
		}
#endif /* DNSS_IPV6 */
		state->mdns_start_time = clock_get(NULL);
		client_timer_set(&state->adv_timer, 2000);
	}
	state->mdns_adv |= adv_mask;
	state->mdns_state = MDNS_PROBE1;
}

void dnss_mdns_stop(u8 adv_mask, int advertise)
{
	struct dnss_state *state = &dnss_state;

	if (advertise) {
		state->mdns_adv_bye = adv_mask;
		dnss_mdns_advertise();
		state->mdns_adv_bye = 0;
	}
	state->mdns_adv &= ~adv_mask;
	if (!state->mdns_adv) {
		client_timer_cancel(&state->adv_timer);
		if (state->mdns_state != MDNS_OFF) {
			state->mdns_state = MDNS_OFF;
		}
		dnss_close_helper(&state->mdns_pcb);
#ifdef DNSS_IPV6
		dnss_close_helper(&state->mdns_pcb_v6);
#endif
	}
}
#endif /* MFI || HOMEKIT */
