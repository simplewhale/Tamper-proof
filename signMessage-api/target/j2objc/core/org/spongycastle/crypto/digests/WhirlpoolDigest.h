//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/WhirlpoolDigest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsWhirlpoolDigest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsWhirlpoolDigest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsWhirlpoolDigest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsWhirlpoolDigest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsWhirlpoolDigest

#if !defined (OrgSpongycastleCryptoDigestsWhirlpoolDigest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsWhirlpoolDigest || defined(INCLUDE_OrgSpongycastleCryptoDigestsWhirlpoolDigest))
#define OrgSpongycastleCryptoDigestsWhirlpoolDigest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

#define RESTRICT_OrgSpongycastleUtilMemoable 1
#define INCLUDE_OrgSpongycastleUtilMemoable 1
#include "org/spongycastle/util/Memoable.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsWhirlpoolDigest : NSObject < OrgSpongycastleCryptoExtendedDigest, OrgSpongycastleUtilMemoable >

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithOrgSpongycastleCryptoDigestsWhirlpoolDigest:(OrgSpongycastleCryptoDigestsWhirlpoolDigest *)originalDigest;

- (id<OrgSpongycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)resetWithOrgSpongycastleUtilMemoable:(id<OrgSpongycastleUtilMemoable>)other;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

#pragma mark Protected

- (void)processBlock;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoDigestsWhirlpoolDigest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsWhirlpoolDigest_init(OrgSpongycastleCryptoDigestsWhirlpoolDigest *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsWhirlpoolDigest *new_OrgSpongycastleCryptoDigestsWhirlpoolDigest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsWhirlpoolDigest *create_OrgSpongycastleCryptoDigestsWhirlpoolDigest_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsWhirlpoolDigest_initWithOrgSpongycastleCryptoDigestsWhirlpoolDigest_(OrgSpongycastleCryptoDigestsWhirlpoolDigest *self, OrgSpongycastleCryptoDigestsWhirlpoolDigest *originalDigest);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsWhirlpoolDigest *new_OrgSpongycastleCryptoDigestsWhirlpoolDigest_initWithOrgSpongycastleCryptoDigestsWhirlpoolDigest_(OrgSpongycastleCryptoDigestsWhirlpoolDigest *originalDigest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsWhirlpoolDigest *create_OrgSpongycastleCryptoDigestsWhirlpoolDigest_initWithOrgSpongycastleCryptoDigestsWhirlpoolDigest_(OrgSpongycastleCryptoDigestsWhirlpoolDigest *originalDigest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsWhirlpoolDigest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsWhirlpoolDigest")