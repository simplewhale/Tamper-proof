//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/DRBGProvider.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDRBGProvider")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngDRBGProvider
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDRBGProvider 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDRBGProvider 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngDRBGProvider

#if !defined (OrgSpongycastleCryptoPrngDRBGProvider_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngDRBGProvider || defined(INCLUDE_OrgSpongycastleCryptoPrngDRBGProvider))
#define OrgSpongycastleCryptoPrngDRBGProvider_

@protocol OrgSpongycastleCryptoPrngDrbgSP80090DRBG;
@protocol OrgSpongycastleCryptoPrngEntropySource;

@protocol OrgSpongycastleCryptoPrngDRBGProvider < JavaObject >

- (id<OrgSpongycastleCryptoPrngDrbgSP80090DRBG>)getWithOrgSpongycastleCryptoPrngEntropySource:(id<OrgSpongycastleCryptoPrngEntropySource>)entropySource;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPrngDRBGProvider)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngDRBGProvider)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDRBGProvider")
