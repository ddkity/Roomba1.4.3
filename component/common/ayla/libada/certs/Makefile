# Copyright 2014 Ayla Networks, Inc.  All rights reserved.

#
# Note that for QCA4010, the shark file must be created on Windows using
# C:> SharkSSLParseCAList.exe -b ca_certs_shark.txt ca_certs.PEM
#

default: ca_certs_der.txt ca_certs_pem.txt

#
# The checked-in files are the .pem certs.
#
CERTS_PEM = \
	entrust-ca-g2-sha256-2048.pem \
	entrust-ca-sha1-2048-sn-0x456b5054.pem \
	valicert-cl2-sha1-1024.pem \
	Baltimore_CyberTrust_Root.pem \
	$(NULL)

CERTS_DER = $(CERTS_PEM:%.pem=%.der)

ca_certs_der.txt: $(CERTS_DER)
	cat $^ > $@

ca_certs_pem.txt: $(CERTS_PEM)
	cat $^ > $@

ca_certs_der.c: $(CERTS_DER)
	@( \
		echo "/*"; \
 		echo " * Copyright 2017 Ayla Networks, Inc.  All rights reserved."; \
		echo " */"; \
		echo "#include <stdlib.h>"; \
		for cert in \
			$(CERTS_DER); \
		do \
			var=$${cert%*.der}; \
			var=$${var//-/_}; \
			var=$${var:0:32}; \
			echo "/*"; \
			echo " * $$cert"; ( \
				openssl x509 -in $$cert -inform der -noout -issuer | awk -F'/' \
					'{print " * Issuer:";for (i=2;i<=NF;i++) if($$i!="")print " *   "$$i;}' \
			); ( \
				openssl x509 -in $$cert -inform der -noout -subject | awk -F'/' \
					'{print " * Subject:";for (i=2;i<=NF;i++) if($$i!="")print " *   "$$i;}' \
			); ( \
				openssl x509 -in $$cert -inform der -noout -startdate -enddate | awk -F= \
					'{print " * "$$1":";print " *    "$$2;}' \
			); \
			echo "*/"; \
			echo "static const unsigned char $$var[] = {"; \
			hexdump -e '12/1 "0x%02x, " "\n"' $$cert | sed -e s/^/\ \ / -e s/\ 0x\ \ ,//g; \
			echo "};"; \
		done; \
		echo "const struct"; \
		echo "{"; \
		echo "	const char *name;"; \
		echo "	const unsigned char *cert;"; \
		echo "	size_t size;"; \
		echo "} ca_certs_der[] = {"; \
		for cert in $(CERTS_DER); do \
	  		var=$${cert%*.der}; \
	  		var=$${var//-/_}; \
	  		var=$${var:0:32}; \
	  		echo "  {"; \
	  		echo "    \"$$cert\","; \
	  		echo "    $$var,"; \
	  		echo "    sizeof($$var)"; \
	  		echo "  },"; \
		done; \
		echo "	{ NULL, NULL, 0 },"; \
		echo "};"; \
	) > $@

%.der: %.pem
	@openssl x509 -in $< -out $@ -inform pem -outform der

#
# Target to display the certs on stdout
#
text: $(CERTS_DER)
	@for cert in $(CERTS_DER); do \
		echo; echo $$cert; \
		openssl x509 -in $$cert -noout -inform der -text; \
	done

clean: 
	rm -f $(CERTS_DER) ca_certs_pem.txt ca_certs_der.c
