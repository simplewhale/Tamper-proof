//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/NonMemoableDigest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsNonMemoableDigest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsNonMemoableDigest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsNonMemoableDigest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsNonMemoableDigest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsNonMemoableDigest

#if !defined (OrgSpongycastleCryptoDigestsNonMemoableDigest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsNonMemoableDigest || defined(INCLUDE_OrgSpongycastleCryptoDigestsNonMemoableDigest))
#define OrgSpongycastleCryptoDigestsNonMemoableDigest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsNonMemoableDigest : NSObject < OrgSpongycastleCryptoExtendedDigest >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoExtendedDigest:(id<OrgSpongycastleCryptoExtendedDigest>)baseDigest;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoDigestsNonMemoableDigest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsNonMemoableDigest_initWithOrgSpongycastleCryptoExtendedDigest_(OrgSpongycastleCryptoDigestsNonMemoableDigest *self, id<OrgSpongycastleCryptoExtendedDigest> baseDigest);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsNonMemoableDigest *new_OrgSpongycastleCryptoDigestsNonMemoableDigest_initWithOrgSpongycastleCryptoExtendedDigest_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsNonMemoableDigest *create_OrgSpongycastleCryptoDigestsNonMemoableDigest_initWithOrgSpongycastleCryptoExtendedDigest_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsNonMemoableDigest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsNonMemoableDigest")
