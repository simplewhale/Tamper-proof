//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsPSKIdentityManager.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentityManager")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsPSKIdentityManager
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentityManager 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentityManager 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsPSKIdentityManager

#if !defined (OrgSpongycastleCryptoTlsTlsPSKIdentityManager_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentityManager || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsPSKIdentityManager))
#define OrgSpongycastleCryptoTlsTlsPSKIdentityManager_

@class IOSByteArray;

@protocol OrgSpongycastleCryptoTlsTlsPSKIdentityManager < JavaObject >

- (IOSByteArray *)getHint;

- (IOSByteArray *)getPSKWithByteArray:(IOSByteArray *)identity;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsPSKIdentityManager)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsPSKIdentityManager)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsPSKIdentityManager")