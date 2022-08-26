//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/SHA256Digest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA256Digest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsSHA256Digest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA256Digest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA256Digest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsSHA256Digest

#if !defined (OrgSpongycastleCryptoDigestsSHA256Digest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA256Digest || defined(INCLUDE_OrgSpongycastleCryptoDigestsSHA256Digest))
#define OrgSpongycastleCryptoDigestsSHA256Digest_

#define RESTRICT_OrgSpongycastleCryptoDigestsGeneralDigest 1
#define INCLUDE_OrgSpongycastleCryptoDigestsGeneralDigest 1
#include "org/spongycastle/crypto/digests/GeneralDigest.h"

#define RESTRICT_OrgSpongycastleCryptoDigestsEncodableDigest 1
#define INCLUDE_OrgSpongycastleCryptoDigestsEncodableDigest 1
#include "org/spongycastle/crypto/digests/EncodableDigest.h"

@class IOSByteArray;
@class IOSIntArray;
@protocol OrgSpongycastleUtilMemoable;

@interface OrgSpongycastleCryptoDigestsSHA256Digest : OrgSpongycastleCryptoDigestsGeneralDigest < OrgSpongycastleCryptoDigestsEncodableDigest >

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState;

- (instancetype)initWithOrgSpongycastleCryptoDigestsSHA256Digest:(OrgSpongycastleCryptoDigestsSHA256Digest *)t;

- (id<OrgSpongycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getDigestSize;

- (IOSByteArray *)getEncodedState;

- (void)reset;

- (void)resetWithOrgSpongycastleUtilMemoable:(id<OrgSpongycastleUtilMemoable>)other;

#pragma mark Protected

- (void)processBlock;

- (void)processLengthWithLong:(jlong)bitLength;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoDigestsSHA256Digest)

inline IOSIntArray *OrgSpongycastleCryptoDigestsSHA256Digest_get_K(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSIntArray *OrgSpongycastleCryptoDigestsSHA256Digest_K;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoDigestsSHA256Digest, K, IOSIntArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA256Digest_init(OrgSpongycastleCryptoDigestsSHA256Digest *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *new_OrgSpongycastleCryptoDigestsSHA256Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *create_OrgSpongycastleCryptoDigestsSHA256Digest_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA256Digest_initWithOrgSpongycastleCryptoDigestsSHA256Digest_(OrgSpongycastleCryptoDigestsSHA256Digest *self, OrgSpongycastleCryptoDigestsSHA256Digest *t);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *new_OrgSpongycastleCryptoDigestsSHA256Digest_initWithOrgSpongycastleCryptoDigestsSHA256Digest_(OrgSpongycastleCryptoDigestsSHA256Digest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *create_OrgSpongycastleCryptoDigestsSHA256Digest_initWithOrgSpongycastleCryptoDigestsSHA256Digest_(OrgSpongycastleCryptoDigestsSHA256Digest *t);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA256Digest_initWithByteArray_(OrgSpongycastleCryptoDigestsSHA256Digest *self, IOSByteArray *encodedState);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *new_OrgSpongycastleCryptoDigestsSHA256Digest_initWithByteArray_(IOSByteArray *encodedState) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA256Digest *create_OrgSpongycastleCryptoDigestsSHA256Digest_initWithByteArray_(IOSByteArray *encodedState);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsSHA256Digest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA256Digest")
