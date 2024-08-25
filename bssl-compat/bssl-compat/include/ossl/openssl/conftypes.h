/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef  ossl_OPENSSL_CONFTYPES_H
# define ossl_OPENSSL_CONFTYPES_H
# pragma once

#ifndef  ossl_OPENSSL_CONF_H
# include "ossl/openssl/conf.h"
#endif

/*
 * The contents of this file are deprecated and will be made opaque
 */
struct ossl_conf_method_st {
    const char *name;
    ossl_CONF *(*create) (ossl_CONF_METHOD *meth);
    int (*init) (ossl_CONF *conf);
    int (*destroy) (ossl_CONF *conf);
    int (*destroy_data) (ossl_CONF *conf);
    int (*load_bio) (ossl_CONF *conf, ossl_BIO *bp, long *eline);
    int (*dump) (const ossl_CONF *conf, ossl_BIO *bp);
    int (*is_number) (const ossl_CONF *conf, char c);
    int (*to_int) (const ossl_CONF *conf, char c);
    int (*load) (ossl_CONF *conf, const char *name, long *eline);
};

struct ossl_conf_st {
    ossl_CONF_METHOD *meth;
    void *meth_data;
    ossl_LHASH_OF(ossl_CONF_VALUE) *data;
    int flag_dollarid;
    int flag_abspath;
    char *includedir;
    ossl_OSSL_LIB_CTX *libctx;
};

#endif
