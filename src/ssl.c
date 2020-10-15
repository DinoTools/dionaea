/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* OpenSSL Pre-1.1.0 compatibility */
/* Taken from OpenSSL 1.1.0 snapshot 20160410 */
static int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/* q is optional */
	if (p == NULL || g == NULL)
		return 0;
	BN_free(dh->p);
	BN_free(dh->q);
	BN_free(dh->g);
	dh->p = p;
	dh->q = q;
	dh->g = g;

	if (q != NULL) {
		dh->length = BN_num_bits(q);
	}

	return 1;
}
#endif

/*
 * Grab well-defined DH parameters from OpenSSL, see the BN_get_rfc*
 * functions in <openssl/bn.h> for all available primes.
 */
static DH *make_dh_params(BIGNUM *(*prime)(BIGNUM *))
{
	DH *dh = DH_new();
	BIGNUM *p, *g;

	if (!dh) {
		return NULL;
	}
	p = prime(NULL);
	g = BN_new();
	if (g != NULL) {
		BN_set_word(g, 2);
	}
	if (!p || !g || !DH_set0_pqg(dh, p, NULL, g)) {
		DH_free(dh);
		BN_free(p);
		BN_free(g);
		return NULL;
	}
	return dh;
}


/* Storage and initialization for DH parameters. */
static struct dhparam {
	BIGNUM *(*const prime)(BIGNUM *); /* function to generate... */
	DH *dh;						   /* ...this, used for keys.... */
	const unsigned int min;		   /* ...of length >= this. */
} dhparams[] = {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	{ get_rfc3526_prime_8192, NULL, 6145 },
	{ get_rfc3526_prime_6144, NULL, 4097 },
	{ get_rfc3526_prime_4096, NULL, 3073 },
	{ get_rfc3526_prime_3072, NULL, 2049 },
	{ get_rfc3526_prime_2048, NULL, 1025 },
	{ get_rfc2409_prime_1024, NULL, 0 }
#else
	{ BN_get_rfc3526_prime_8192, NULL, 6145 },
	{ BN_get_rfc3526_prime_6144, NULL, 4097 },
	{ BN_get_rfc3526_prime_4096, NULL, 3073 },
	{ BN_get_rfc3526_prime_3072, NULL, 2049 },
	{ BN_get_rfc3526_prime_2048, NULL, 1025 },
	{ BN_get_rfc2409_prime_1024, NULL, 0 }
#endif
};


void init_dh_params(void)
{
	unsigned n;

	for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
		dhparams[n].dh = make_dh_params(dhparams[n].prime);
}

static void free_dh_params(void)
{
	unsigned n;

	/* DH_free() is a noop for a NULL parameter, so these are harmless
	 * in the (unexpected) case where these variables are already
	 * NULL. */
	for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++) {
		DH_free(dhparams[n].dh);
		dhparams[n].dh = NULL;
	}
}


DH *ssl_dh_GetTmpParam(unsigned keylen)
{
	unsigned n;

	for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
		if (keylen >= dhparams[n].min)
			return dhparams[n].dh;

   return NULL; /* impossible to reach. */
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
	free_dh_params();
	MYSSL_TMP_KEYS_FREE(con, RSA);
}


int ssl_tmp_key_init_rsa(struct connection *con, int bits, int idx)
{
/*	if( !(con->transport.tls.pTmpKeys[idx] = RSA_generate_key(bits, RSA_F4, NULL, NULL)) )
	{
		g_error("Init: Failed to generate temporary %d bit RSA private key", bits);
		return -1;
	}
*/
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

//	g_message("Init: Generating temporary DH parameters (512/1024 bits)");

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
/* TODO: Rewrite
static void callback(int p, int n, void *arg)
{
	char c='B';

	if( p == 0 ) c='.';
	if( p == 1 ) c='+';
	if( p == 2 ) c='*';
	if( p == 3 ) c='\n';
	fputc(c,stderr);
}
*/


bool mkcert(SSL_CTX *ctx)
{
	int bits = 512*4;
	int serial = time(NULL);
	int days = 365;
	gchar *value = NULL;
	GError *error = NULL;

	int ret = 0;
	bool res = false;
	BIGNUM *bne = NULL;
	unsigned long e = RSA_F4;

	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa  = NULL;
	X509_NAME *name=NULL;

	if( (pk=EVP_PKEY_new()) == NULL )
		goto free_all;

	if( (x=X509_new()) == NULL )
		goto free_all;

	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	rsa = RSA_new();
	//ret = RSA_generate_key_ex(rsa, bits, bne, callback);
	ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
	if(ret != 1) {
		g_error("Init: Failed to generate temporary %d bit RSA private key", bits);
		goto free_all;
	}
	if( !EVP_PKEY_assign_RSA(pk,rsa) )
	{
		perror("EVP_PKEY_assign_RSA");
		goto free_all;
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
		goto free_all;


	ret = SSL_CTX_use_PrivateKey(ctx, pk);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey");
		goto free_all;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_certificate");
		goto free_all;
	}

	res = true;
free_all:
	BN_free(bne);

	return res;
}
