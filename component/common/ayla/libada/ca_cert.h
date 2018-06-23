/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CA_CERT_H__
#define __AYLA_CA_CERT_H__

#ifdef AMEBA
struct raw_der_cert {
	const char *name;
	const unsigned char *cert;
	size_t size;
};

extern struct raw_der_cert ca_certs_der[];

#define CA_CERT ca_certs_der
#define CA_CERT_SIZE 0
#else
#include <ada/linker_text.h>

/*
 * CA_CERT file is incorporated into the build by the linker.
 * objcopy provides these symbols.
 */
#ifdef WMSDK
#define CA_CERT_FILE	ca_certs_pem_txt
#elif defined(QCA4010)
#define CA_CERT_FILE	ca_certs_shark_txt	/* generated in Windows */
#else
#define CA_CERT_FILE	ca_certs_der_txt
#endif /* WMSDK */

LINKER_TEXT_ARRAY_DECLARE(CA_CERT_FILE);
LINKER_TEXT_SIZE_DECLARE(CA_CERT_FILE);

#define CA_CERT		LINKER_TEXT_START(CA_CERT_FILE)
#define CA_CERT_SIZE	((size_t)LINKER_TEXT_SIZE(CA_CERT_FILE))
#endif /* AMEBA */

#endif /* __AYLA_CA_CERT_H__ */
