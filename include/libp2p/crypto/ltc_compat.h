#ifndef LIBP2P_CRYPTO_LTC_COMPAT_H
#define LIBP2P_CRYPTO_LTC_COMPAT_H

#define ed25519_export ltc_ed25519_export
#define ed25519_import ltc_ed25519_import
#define ed25519_import_pkcs8 ltc_ed25519_import_pkcs8
#define ed25519_import_raw ltc_ed25519_import_raw
#define ed25519_import_x509 ltc_ed25519_import_x509
#define ed25519_make_key ltc_ed25519_make_key
#define ed25519_sign ltc_ed25519_sign
#define ed25519_verify ltc_ed25519_verify
#define ed25519ctx_verify ltc_ed25519ctx_verify
#define ed25519ph_verify ltc_ed25519ph_verify

#define x25519_export ltc_x25519_export
#define x25519_import ltc_x25519_import
#define x25519_import_pkcs8 ltc_x25519_import_pkcs8
#define x25519_import_raw ltc_x25519_import_raw
#define x25519_import_x509 ltc_x25519_import_x509
#define x25519_make_key ltc_x25519_make_key
#define x25519_shared_secret ltc_x25519_shared_secret

#include "../../external/libtomcrypt/src/headers/tomcrypt.h"

#endif /* LIBP2P_CRYPTO_LTC_COMPAT_H */
