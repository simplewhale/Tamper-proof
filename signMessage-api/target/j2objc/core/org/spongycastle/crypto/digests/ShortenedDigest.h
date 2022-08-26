//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/ShortenedDigest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsShortenedDigest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsShortenedDigest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsShortenedDigest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsShortenedDigest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsShortenedDigest

#if !defined (OrgSpongycastleCryptoDigestsShortenedDigest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsShortenedDigest || defined(INCLUDE_OrgSpongycastleCryptoDigestsShortenedDigest))
#define OrgSpongycastleCryptoDigestsShortenedDigest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsShortenedDigest : NSObject < OrgSpongycastleCryptoExtendedDigest >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoExtendedDigest:(id<OrgSpongycastleCryptoExtendedDigest>)baseDigest
                                                    withInt:(jint)length;

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

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoDigestsShortenedDigest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(OrgSpongycastleCryptoDigestsShortenedDigest *self, id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsShortenedDigest *new_OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsShortenedDigest *create_OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsShortenedDigest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsShortenedDigest")
