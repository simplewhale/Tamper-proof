//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/RIPEMD128Digest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsRIPEMD128Digest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsRIPEMD128Digest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsRIPEMD128Digest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsRIPEMD128Digest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsRIPEMD128Digest

#if !defined (OrgSpongycastleCryptoDigestsRIPEMD128Digest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsRIPEMD128Digest || defined(INCLUDE_OrgSpongycastleCryptoDigestsRIPEMD128Digest))
#define OrgSpongycastleCryptoDigestsRIPEMD128Digest_

#define RESTRICT_OrgSpongycastleCryptoDigestsGeneralDigest 1
#define INCLUDE_OrgSpongycastleCryptoDigestsGeneralDigest 1
#include "org/spongycastle/crypto/digests/GeneralDigest.h"

@class IOSByteArray;
@protocol OrgSpongycastleUtilMemoable;

@interface OrgSpongycastleCryptoDigestsRIPEMD128Digest : OrgSpongycastleCryptoDigestsGeneralDigest

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithOrgSpongycastleCryptoDigestsRIPEMD128Digest:(OrgSpongycastleCryptoDigestsRIPEMD128Digest *)t;

- (id<OrgSpongycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getDigestSize;

- (void)reset;

- (void)resetWithOrgSpongycastleUtilMemoable:(id<OrgSpongycastleUtilMemoable>)other;

#pragma mark Protected

- (void)processBlock;

- (void)processLengthWithLong:(jlong)bitLength;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoDigestsRIPEMD128Digest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsRIPEMD128Digest_init(OrgSpongycastleCryptoDigestsRIPEMD128Digest *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsRIPEMD128Digest *new_OrgSpongycastleCryptoDigestsRIPEMD128Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsRIPEMD128Digest *create_OrgSpongycastleCryptoDigestsRIPEMD128Digest_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsRIPEMD128Digest_initWithOrgSpongycastleCryptoDigestsRIPEMD128Digest_(OrgSpongycastleCryptoDigestsRIPEMD128Digest *self, OrgSpongycastleCryptoDigestsRIPEMD128Digest *t);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsRIPEMD128Digest *new_OrgSpongycastleCryptoDigestsRIPEMD128Digest_initWithOrgSpongycastleCryptoDigestsRIPEMD128Digest_(OrgSpongycastleCryptoDigestsRIPEMD128Digest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsRIPEMD128Digest *create_OrgSpongycastleCryptoDigestsRIPEMD128Digest_initWithOrgSpongycastleCryptoDigestsRIPEMD128Digest_(OrgSpongycastleCryptoDigestsRIPEMD128Digest *t);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsRIPEMD128Digest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsRIPEMD128Digest")
