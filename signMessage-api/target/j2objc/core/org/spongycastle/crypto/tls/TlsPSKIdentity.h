//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsPSKIdentity.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentity")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsPSKIdentity
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentity 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentity 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsPSKIdentity

#if !defined (OrgSpongycastleCryptoTlsTlsPSKIdentity_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentity || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsPSKIdentity))
#define OrgSpongycastleCryptoTlsTlsPSKIdentity_

@class IOSByteArray;

@protocol OrgSpongycastleCryptoTlsTlsPSKIdentity < JavaObject >

- (void)skipIdentityHint;

- (void)notifyIdentityHintWithByteArray:(IOSByteArray *)psk_identity_hint;

- (IOSByteArray *)getPSKIdentity;

- (IOSByteArray *)getPSK;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsPSKIdentity)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsPSKIdentity)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentity")
