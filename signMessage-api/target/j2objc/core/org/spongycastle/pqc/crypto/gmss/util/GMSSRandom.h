//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/gmss/util/GMSSRandom.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom

#if !defined (OrgSpongycastlePqcCryptoGmssUtilGMSSRandom_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom || defined(INCLUDE_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom))
#define OrgSpongycastlePqcCryptoGmssUtilGMSSRandom_

@class IOSByteArray;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastlePqcCryptoGmssUtilGMSSRandom : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)messDigestTree2;

- (IOSByteArray *)nextSeedWithByteArray:(IOSByteArray *)outseed;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoGmssUtilGMSSRandom)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoGmssUtilGMSSRandom_initWithOrgSpongycastleCryptoDigest_(OrgSpongycastlePqcCryptoGmssUtilGMSSRandom *self, id<OrgSpongycastleCryptoDigest> messDigestTree2);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoGmssUtilGMSSRandom *new_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> messDigestTree2) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoGmssUtilGMSSRandom *create_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> messDigestTree2);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoGmssUtilGMSSRandom)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSRandom")