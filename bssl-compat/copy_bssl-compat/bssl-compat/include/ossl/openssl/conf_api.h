/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef  ossl_OPENSSL_CONF_API_H
# define ossl_OPENSSL_CONF_API_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_CONF_API_H
# endif

# include "ossl/openssl/lhash.h"
# include "ossl/openssl/conf.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Up until OpenSSL 0.9.5a, this was new_section */
ossl_CONF_VALUE *ossl__CONF_new_section(ossl_CONF *conf, const char *section);
/* Up until OpenSSL 0.9.5a, this was get_section */
ossl_CONF_VALUE *ossl__CONF_get_section(const ossl_CONF *conf, const char *section);
/* Up until OpenSSL 0.9.5a, this was ossl_CONF_get_section */
ossl_STACK_OF(ossl_CONF_VALUE) *ossl__CONF_get_section_values(const ossl_CONF *conf,
                                               const char *section);

int ossl__CONF_add_string(ossl_CONF *conf, ossl_CONF_VALUE *section, ossl_CONF_VALUE *value);
char *ossl__CONF_get_string(const ossl_CONF *conf, const char *section,
                       const char *name);
long ossl__CONF_get_number(const ossl_CONF *conf, const char *section,
                      const char *name);

int ossl__CONF_new_data(ossl_CONF *conf);
void ossl__CONF_free_data(ossl_CONF *conf);

#ifdef  __cplusplus
}
#endif
#endif
