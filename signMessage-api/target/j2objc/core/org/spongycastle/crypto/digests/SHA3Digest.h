//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/SHA3Digest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA3Digest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsSHA3Digest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA3Digest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA3Digest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsSHA3Digest

#if !defined (OrgSpongycastleCryptoDigestsSHA3Digest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA3Digest || defined(INCLUDE_OrgSpongycastleCryptoDigestsSHA3Digest))
#define OrgSpongycastleCryptoDigestsSHA3Digest_

#define RESTRICT_OrgSpongycastleCryptoDigestsKeccakDigest 1
#define INCLUDE_OrgSpongycastleCryptoDigestsKeccakDigest 1
#include "org/spongycastle/crypto/digests/KeccakDigest.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsSHA3Digest : OrgSpongycastleCryptoDigestsKeccakDigest

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithInt:(jint)bitLength;

- (instancetype)initWithOrgSpongycastleCryptoDigestsSHA3Digest:(OrgSpongycastleCryptoDigestsSHA3Digest *)source;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

#pragma mark Protected

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff
                    withByte:(jbyte)partialByte
                     withInt:(jint)partialBits;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigestsKeccakDigest:(OrgSpongycastleCryptoDigestsKeccakDigest *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoDigestsSHA3Digest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA3Digest_init(OrgSpongycastleCryptoDigestsSHA3Digest *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *new_OrgSpongycastleCryptoDigestsSHA3Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *create_OrgSpongycastleCryptoDigestsSHA3Digest_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA3Digest_initWithInt_(OrgSpongycastleCryptoDigestsSHA3Digest *self, jint bitLength);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *new_OrgSpongycastleCryptoDigestsSHA3Digest_initWithInt_(jint bitLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *create_OrgSpongycastleCryptoDigestsSHA3Digest_initWithInt_(jint bitLength);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSHA3Digest_initWithOrgSpongycastleCryptoDigestsSHA3Digest_(OrgSpongycastleCryptoDigestsSHA3Digest *self, OrgSpongycastleCryptoDigestsSHA3Digest *source);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *new_OrgSpongycastleCryptoDigestsSHA3Digest_initWithOrgSpongycastleCryptoDigestsSHA3Digest_(OrgSpongycastleCryptoDigestsSHA3Digest *source) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSHA3Digest *create_OrgSpongycastleCryptoDigestsSHA3Digest_initWithOrgSpongycastleCryptoDigestsSHA3Digest_(OrgSpongycastleCryptoDigestsSHA3Digest *source);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsSHA3Digest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSHA3Digest")
