/*
 * Copyright 2000-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2018-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_HTTP_H
# define ossl_OPENSSL_HTTP_H
# pragma once

# include "ossl/openssl/opensslconf.h"

# include "ossl/openssl/bio.h"
# include "ossl/openssl/asn1.h"
# include "ossl/openssl/conf.h"


# ifdef __cplusplus
extern "C" {
# endif

# define ossl_OSSL_HTTP_NAME "http"
# define ossl_OSSL_HTTPS_NAME "https"
# define ossl_OSSL_HTTP_PREFIX ossl_OSSL_HTTP_NAME"://"
# define ossl_OSSL_HTTPS_PREFIX ossl_OSSL_HTTPS_NAME"://"
# define ossl_OSSL_HTTP_PORT "80"
# define ossl_OSSL_HTTPS_PORT "443"
# define ossl_OPENSSL_NO_PROXY "NO_PROXY"
# define ossl_OPENSSL_HTTP_PROXY "HTTP_PROXY"
# define ossl_OPENSSL_HTTPS_PROXY "HTTPS_PROXY"

#define ossl_OSSL_HTTP_DEFAULT_MAX_LINE_LEN (4 * 1024)
#define ossl_OSSL_HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)

/* Low-level HTTP API */
ossl_OSSL_HTTP_REQ_CTX *ossl_OSSL_HTTP_REQ_CTX_new(ossl_BIO *wbio, ossl_BIO *rbio, int buf_size);
void ossl_OSSL_HTTP_REQ_CTX_free(ossl_OSSL_HTTP_REQ_CTX *rctx);
int ossl_OSSL_HTTP_REQ_CTX_set_request_line(ossl_OSSL_HTTP_REQ_CTX *rctx, int method_POST,
                                       const char *server, const char *port,
                                       const char *path);
int ossl_OSSL_HTTP_REQ_CTX_add1_header(ossl_OSSL_HTTP_REQ_CTX *rctx,
                                  const char *name, const char *value);
int ossl_OSSL_HTTP_REQ_CTX_set_expected(ossl_OSSL_HTTP_REQ_CTX *rctx,
                                   const char *content_type, int asn1,
                                   int timeout, int keep_alive);
int ossl_OSSL_HTTP_REQ_CTX_set1_req(ossl_OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
                               const ossl_ASN1_ITEM *it, const ossl_ASN1_VALUE *req);
int ossl_OSSL_HTTP_REQ_CTX_nbio(ossl_OSSL_HTTP_REQ_CTX *rctx);
int ossl_OSSL_HTTP_REQ_CTX_nbio_d2i(ossl_OSSL_HTTP_REQ_CTX *rctx,
                               ossl_ASN1_VALUE **pval, const ossl_ASN1_ITEM *it);
ossl_BIO *ossl_OSSL_HTTP_REQ_CTX_exchange(ossl_OSSL_HTTP_REQ_CTX *rctx);
ossl_BIO *ossl_OSSL_HTTP_REQ_CTX_get0_mem_bio(const ossl_OSSL_HTTP_REQ_CTX *rctx);
size_t ossl_OSSL_HTTP_REQ_CTX_get_resp_len(const ossl_OSSL_HTTP_REQ_CTX *rctx);
void ossl_OSSL_HTTP_REQ_CTX_set_max_response_length(ossl_OSSL_HTTP_REQ_CTX *rctx,
                                               unsigned long len);
int ossl_OSSL_HTTP_is_alive(const ossl_OSSL_HTTP_REQ_CTX *rctx);

/* High-level HTTP API */
typedef ossl_BIO *(*ossl_OSSL_HTTP_bio_cb_t)(ossl_BIO *bio, void *arg, int connect, int detail);
ossl_OSSL_HTTP_REQ_CTX *ossl_OSSL_HTTP_open(const char *server, const char *port,
                                  const char *proxy, const char *no_proxy,
                                  int use_ssl, ossl_BIO *bio, ossl_BIO *rbio,
                                  ossl_OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                                  int buf_size, int overall_timeout);
int ossl_OSSL_HTTP_proxy_connect(ossl_BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            int timeout, ossl_BIO *bio_err, const char *prog);
int ossl_OSSL_HTTP_set1_request(ossl_OSSL_HTTP_REQ_CTX *rctx, const char *path,
                           const ossl_STACK_OF(ossl_CONF_VALUE) *headers,
                           const char *content_type, ossl_BIO *req,
                           const char *expected_content_type, int expect_asn1,
                           size_t max_resp_len, int timeout, int keep_alive);
ossl_BIO *ossl_OSSL_HTTP_exchange(ossl_OSSL_HTTP_REQ_CTX *rctx, char **redirection_url);
ossl_BIO *ossl_OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy,
                   ossl_BIO *bio, ossl_BIO *rbio,
                   ossl_OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                   int buf_size, const ossl_STACK_OF(ossl_CONF_VALUE) *headers,
                   const char *expected_content_type, int expect_asn1,
                   size_t max_resp_len, int timeout);
ossl_BIO *ossl_OSSL_HTTP_transfer(ossl_OSSL_HTTP_REQ_CTX **prctx,
                        const char *server, const char *port,
                        const char *path, int use_ssl,
                        const char *proxy, const char *no_proxy,
                        ossl_BIO *bio, ossl_BIO *rbio,
                        ossl_OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                        int buf_size, const ossl_STACK_OF(ossl_CONF_VALUE) *headers,
                        const char *content_type, ossl_BIO *req,
                        const char *expected_content_type, int expect_asn1,
                        size_t max_resp_len, int timeout, int keep_alive);
int ossl_OSSL_HTTP_close(ossl_OSSL_HTTP_REQ_CTX *rctx, int ok);

/* Auxiliary functions */
int ossl_OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
                   char **pport, int *pport_num,
                   char **ppath, char **pquery, char **pfrag);
int ossl_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
                        char **pport, int *pport_num,
                        char **ppath, char **pquery, char **pfrag);
const char *ossl_OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
                                  const char *server, int use_ssl);

# ifdef  __cplusplus
}
# endif
#endif /* !defined(ossl_OPENSSL_HTTP_H) */
