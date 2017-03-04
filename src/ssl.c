/********************************************************************************
 *                               Dionaea
 *                           - catches bugs -
 *
 *
 *
 * Copyright (C) 2009  Paul Baecher & Markus Koetter
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *
 *             contact nepenthesdev@gmail.com
 *
 *******************************************************************************/

#include "config.h"

#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>


#include <sys/time.h>
#include <time.h>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#include <glib.h>

#define D_LOG_DOMAIN "connection"

#define CL g_dionaea->loop

#include "dionaea.h"
#include "connection.h"
#include "log.h"


int ssl_tmp_keys_init(struct connection *con);


/*
 *
 * connection ssl
 *
 */

/*
 * the ssl dh key setup is taken from the mod_ssl package from apache
 */

#ifndef SSLC_VERSION_NUMBER
#define SSLC_VERSION_NUMBER 0x0000
#endif

DH *myssl_dh_configure(unsigned char *p, int plen,
					   unsigned char *g, int glen)
{
	DH *dh;

	if( !(dh = DH_new()) )
	{
		return NULL;
	}

#if defined(OPENSSL_VERSION_NUMBER) || (SSLC_VERSION_NUMBER < 0x2000)
	dh->p = BN_bin2bn(p, plen, NULL);
	dh->g = BN_bin2bn(g, glen, NULL);
	if( !(dh->p && dh->g) )
	{
		DH_free(dh);
		return NULL;
	}
#else
	R_EITEMS_add(dh->data, PK_TYPE_DH, PK_DH_P, 0, p, plen, R_EITEMS_PF_COPY);
	R_EITEMS_add(dh->data, PK_TYPE_DH, PK_DH_G, 0, g, glen, R_EITEMS_PF_COPY);
#endif

	return dh;
}





/*
 * Handle the Temporary RSA Keys and DH Params
 */


/*
** Diffie-Hellman-Parameters: (512 bit)
**     prime:
**         00:9f:db:8b:8a:00:45:44:f0:04:5f:17:37:d0:ba:
**         2e:0b:27:4c:df:1a:9f:58:82:18:fb:43:53:16:a1:
**         6e:37:41:71:fd:19:d8:d8:f3:7c:39:bf:86:3f:d6:
**         0e:3e:30:06:80:a3:03:0c:6e:4c:37:57:d0:8f:70:
**         e6:aa:87:10:33
**     generator: 2 (0x2)
** Diffie-Hellman-Parameters: (1024 bit)
**     prime:
**         00:d6:7d:e4:40:cb:bb:dc:19:36:d6:93:d3:4a:fd:
**         0a:d5:0c:84:d2:39:a4:5f:52:0b:b8:81:74:cb:98:
**         bc:e9:51:84:9f:91:2e:63:9c:72:fb:13:b4:b4:d7:
**         17:7e:16:d5:5a:c1:79:ba:42:0b:2a:29:fe:32:4a:
**         46:7a:63:5e:81:ff:59:01:37:7b:ed:dc:fd:33:16:
**         8a:46:1a:ad:3b:72:da:e8:86:00:78:04:5b:07:a7:
**         db:ca:78:74:08:7d:15:10:ea:9f:cc:9d:dd:33:05:
**         07:dd:62:db:88:ae:aa:74:7d:e0:f4:d6:e2:bd:68:
**         b0:e7:39:3e:0f:24:21:8e:b3
**     generator: 2 (0x2)
*/

static unsigned char dh512_p[] = {
	0x9F, 0xDB, 0x8B, 0x8A, 0x00, 0x45, 0x44, 0xF0, 0x04, 0x5F, 0x17, 0x37,
	0xD0, 0xBA, 0x2E, 0x0B, 0x27, 0x4C, 0xDF, 0x1A, 0x9F, 0x58, 0x82, 0x18,
	0xFB, 0x43, 0x53, 0x16, 0xA1, 0x6E, 0x37, 0x41, 0x71, 0xFD, 0x19, 0xD8,
	0xD8, 0xF3, 0x7C, 0x39, 0xBF, 0x86, 0x3F, 0xD6, 0x0E, 0x3E, 0x30, 0x06,
	0x80, 0xA3, 0x03, 0x0C, 0x6E, 0x4C, 0x37, 0x57, 0xD0, 0x8F, 0x70, 0xE6,
	0xAA, 0x87, 0x10, 0x33,
};
static unsigned char dh512_g[] = {
	0x02,
};

static DH *get_dh512(void)
{
	return myssl_dh_configure(dh512_p, sizeof(dh512_p),
							  dh512_g, sizeof(dh512_g));
}

static unsigned char dh1024_p[] = {
	0xD6, 0x7D, 0xE4, 0x40, 0xCB, 0xBB, 0xDC, 0x19, 0x36, 0xD6, 0x93, 0xD3,
	0x4A, 0xFD, 0x0A, 0xD5, 0x0C, 0x84, 0xD2, 0x39, 0xA4, 0x5F, 0x52, 0x0B,
	0xB8, 0x81, 0x74, 0xCB, 0x98, 0xBC, 0xE9, 0x51, 0x84, 0x9F, 0x91, 0x2E,
	0x63, 0x9C, 0x72, 0xFB, 0x13, 0xB4, 0xB4, 0xD7, 0x17, 0x7E, 0x16, 0xD5,
	0x5A, 0xC1, 0x79, 0xBA, 0x42, 0x0B, 0x2A, 0x29, 0xFE, 0x32, 0x4A, 0x46,
	0x7A, 0x63, 0x5E, 0x81, 0xFF, 0x59, 0x01, 0x37, 0x7B, 0xED, 0xDC, 0xFD,
	0x33, 0x16, 0x8A, 0x46, 0x1A, 0xAD, 0x3B, 0x72, 0xDA, 0xE8, 0x86, 0x00,
	0x78, 0x04, 0x5B, 0x07, 0xA7, 0xDB, 0xCA, 0x78, 0x74, 0x08, 0x7D, 0x15,
	0x10, 0xEA, 0x9F, 0xCC, 0x9D, 0xDD, 0x33, 0x05, 0x07, 0xDD, 0x62, 0xDB,
	0x88, 0xAE, 0xAA, 0x74, 0x7D, 0xE0, 0xF4, 0xD6, 0xE2, 0xBD, 0x68, 0xB0,
	0xE7, 0x39, 0x3E, 0x0F, 0x24, 0x21, 0x8E, 0xB3,
};
static unsigned char dh1024_g[] = {
	0x02,
};

static DH *get_dh1024(void)
{
	return myssl_dh_configure(dh1024_p, sizeof(dh1024_p),
							  dh1024_g, sizeof(dh1024_g));
}

/* ----END GENERATED SECTION---------- */

DH *ssl_dh_GetTmpParam(int nKeyLen)
{
	DH *dh;

	if( nKeyLen == 512 )
		dh = get_dh512();
	else
		dh = get_dh1024();
	return dh;
}

DH *ssl_dh_GetParamFromFile(char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if( (bio = BIO_new_file(file, "r")) == NULL )
		return NULL;
#if 0 //SSL_LIBRARY_VERSION < 0x00904000
	dh = PEM_read_bio_DHparams(bio, NULL, NULL);
#else
	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
#endif
	BIO_free(bio);
	return(dh);
}


#define MYSSL_TMP_KEY_FREE(con, type, idx) \
    if (con->transport.tls.pTmpKeys[idx]) { \
        type##_free((type *)con->transport.tls.pTmpKeys[idx]); \
        con->transport.tls.pTmpKeys[idx] = NULL; \
    }

#define MYSSL_TMP_KEYS_FREE(con, type) \
    MYSSL_TMP_KEY_FREE(con, type, SSL_TMP_KEY_##type##_512); \
    MYSSL_TMP_KEY_FREE(con, type, SSL_TMP_KEY_##type##_1024)

void ssl_tmp_keys_free(struct connection *con)
{
	MYSSL_TMP_KEYS_FREE(con, RSA);
	MYSSL_TMP_KEYS_FREE(con, DH);
}

int ssl_tmp_key_init_rsa(struct connection *con, int bits, int idx)
{
	if( !(con->transport.tls.pTmpKeys[idx] = RSA_generate_key(bits, RSA_F4, NULL, NULL)) )
	{
		g_error("Init: Failed to generate temporary %d bit RSA private key", bits);
		return -1;
	}

	return 0;
}

static int ssl_tmp_key_init_dh(struct connection *con, int bits, int idx)
{
	if( !(con->transport.tls.pTmpKeys[idx] = ssl_dh_GetTmpParam(bits)) )
	{
		g_error("Init: Failed to generate temporary %d bit DH parameters", bits);
		return -1;
	}

	return 0;
}

#define MYSSL_TMP_KEY_INIT_RSA(s, bits) \
    ssl_tmp_key_init_rsa(s, bits, SSL_TMP_KEY_RSA_##bits)

#define MYSSL_TMP_KEY_INIT_DH(s, bits) \
    ssl_tmp_key_init_dh(s, bits, SSL_TMP_KEY_DH_##bits)

int ssl_tmp_keys_init(struct connection *con)
{

	g_message("Init: Generating temporary RSA private keys (512/1024 bits)");

	if( MYSSL_TMP_KEY_INIT_RSA(con, 512) ||
		MYSSL_TMP_KEY_INIT_RSA(con, 1024) )
	{
		return -1;
	}

	g_message("Init: Generating temporary DH parameters (512/1024 bits)");

	if( MYSSL_TMP_KEY_INIT_DH(con, 512) ||
		MYSSL_TMP_KEY_INIT_DH(con, 1024) )
	{
		return -1;
	}

	return 0;
}

int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if( !ex )
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

static void callback(int p, int n, void *arg)
{
	char c='B';

	if( p == 0 ) c='.';
	if( p == 1 ) c='+';
	if( p == 2 ) c='*';
	if( p == 3 ) c='\n';
	fputc(c,stderr);
}


bool mkcert(SSL_CTX *ctx)
{
	int bits = 512*4;
	int serial = time(NULL);
	int days = 365;
	gchar *value = NULL;
	GError *error = NULL;


	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;

	if( (pk=EVP_PKEY_new()) == NULL )
		goto err;

	if( (x=X509_new()) == NULL )
		goto err;

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if( !EVP_PKEY_assign_RSA(pk,rsa) )
	{
		perror("EVP_PKEY_assign_RSA");
		goto err;
	}
	rsa=NULL;

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.c", &error);
	if (value == NULL) {
		value = g_strdup("DE");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.cn", &error);
	if (value == NULL) {
		value = g_strdup("Nepenthes Development Team");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.o", &error);
	if (value == NULL) {
		value = g_strdup("dionaea.carnivore.it");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.ou", &error);
	if (value == NULL) {
		value = g_strdup("anv");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);


	/* Its self signed so set the issuer name to be the same as the
	 * subject.
	 */
	X509_set_issuer_name(x,name);

	add_ext(x, NID_netscape_cert_type, "server");
	add_ext(x, NID_netscape_ssl_server_name, "localhost");

	if( !X509_sign(x,pk,EVP_md5()) )
		goto err;


	int ret = SSL_CTX_use_PrivateKey(ctx, pk);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey");
		return false;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_certificate");
		return false;
	}

	return true;
	err:
	return false;
}
