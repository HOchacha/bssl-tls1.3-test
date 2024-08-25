/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PROVIDER_H
# define ossl_OPENSSL_PROVIDER_H
# pragma once

# include "ossl/openssl/core.h"

# ifdef __cplusplus
extern "C" {
# endif

/* Set the default provider search path */
int ossl_OSSL_PROVIDER_set_default_search_path(ossl_OSSL_LIB_CTX *, const char *path);

/* Load and unload a provider */
ossl_OSSL_PROVIDER *ossl_OSSL_PROVIDER_load(ossl_OSSL_LIB_CTX *, const char *name);
ossl_OSSL_PROVIDER *ossl_OSSL_PROVIDER_try_load(ossl_OSSL_LIB_CTX *, const char *name,
                                      int retain_fallbacks);
int ossl_OSSL_PROVIDER_unload(ossl_OSSL_PROVIDER *prov);
int ossl_OSSL_PROVIDER_available(ossl_OSSL_LIB_CTX *, const char *name);
int ossl_OSSL_PROVIDER_do_all(ossl_OSSL_LIB_CTX *ctx,
                         int (*cb)(ossl_OSSL_PROVIDER *provider, void *cbdata),
                         void *cbdata);

const ossl_OSSL_PARAM *ossl_OSSL_PROVIDER_gettable_params(const ossl_OSSL_PROVIDER *prov);
int ossl_OSSL_PROVIDER_get_params(const ossl_OSSL_PROVIDER *prov, ossl_OSSL_PARAM params[]);
int ossl_OSSL_PROVIDER_self_test(const ossl_OSSL_PROVIDER *prov);
int ossl_OSSL_PROVIDER_get_capabilities(const ossl_OSSL_PROVIDER *prov,
                                   const char *capability,
                                   ossl_OSSL_CALLBACK *cb,
                                   void *arg);

const ossl_OSSL_ALGORITHM *ossl_OSSL_PROVIDER_query_operation(const ossl_OSSL_PROVIDER *prov,
                                                    int operation_id,
                                                    int *no_cache);
void ossl_OSSL_PROVIDER_unquery_operation(const ossl_OSSL_PROVIDER *prov,
                                     int operation_id, const ossl_OSSL_ALGORITHM *algs);
void *ossl_OSSL_PROVIDER_get0_provider_ctx(const ossl_OSSL_PROVIDER *prov);
const ossl_OSSL_DISPATCH *ossl_OSSL_PROVIDER_get0_dispatch(const ossl_OSSL_PROVIDER *prov);

/* Add a built in providers */
int ossl_OSSL_PROVIDER_add_builtin(ossl_OSSL_LIB_CTX *, const char *name,
                              ossl_OSSL_provider_init_fn *init_fn);

/* Information */
const char *ossl_OSSL_PROVIDER_get0_name(const ossl_OSSL_PROVIDER *prov);

# ifdef __cplusplus
}
# endif

#endif
