//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/DSTU7564Digest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsDSTU7564Digest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsDSTU7564Digest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsDSTU7564Digest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsDSTU7564Digest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsDSTU7564Digest

#if !defined (OrgSpongycastleCryptoDigestsDSTU7564Digest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsDSTU7564Digest || defined(INCLUDE_OrgSpongycastleCryptoDigestsDSTU7564Digest))
#define OrgSpongycastleCryptoDigestsDSTU7564Digest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

#define RESTRICT_OrgSpongycastleUtilMemoable 1
#define INCLUDE_OrgSpongycastleUtilMemoable 1
#include "org/spongycastle/util/Memoable.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsDSTU7564Digest : NSObject < OrgSpongycastleCryptoExtendedDigest, OrgSpongycastleUtilMemoable >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoDigestsDSTU7564Digest:(OrgSpongycastleCryptoDigestsDSTU7564Digest *)digest;

- (instancetype)initWithInt:(jint)hashSizeBits;

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

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoDigestsDSTU7564Digest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithOrgSpongycastleCryptoDigestsDSTU7564Digest_(OrgSpongycastleCryptoDigestsDSTU7564Digest *self, OrgSpongycastleCryptoDigestsDSTU7564Digest *digest);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsDSTU7564Digest *new_OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithOrgSpongycastleCryptoDigestsDSTU7564Digest_(OrgSpongycastleCryptoDigestsDSTU7564Digest *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsDSTU7564Digest *create_OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithOrgSpongycastleCryptoDigestsDSTU7564Digest_(OrgSpongycastleCryptoDigestsDSTU7564Digest *digest);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithInt_(OrgSpongycastleCryptoDigestsDSTU7564Digest *self, jint hashSizeBits);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsDSTU7564Digest *new_OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithInt_(jint hashSizeBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsDSTU7564Digest *create_OrgSpongycastleCryptoDigestsDSTU7564Digest_initWithInt_(jint hashSizeBits);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsDSTU7564Digest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsDSTU7564Digest")
