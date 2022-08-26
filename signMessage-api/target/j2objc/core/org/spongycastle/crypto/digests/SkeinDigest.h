//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/SkeinDigest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSkeinDigest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsSkeinDigest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSkeinDigest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsSkeinDigest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsSkeinDigest

#if !defined (OrgSpongycastleCryptoDigestsSkeinDigest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsSkeinDigest || defined(INCLUDE_OrgSpongycastleCryptoDigestsSkeinDigest))
#define OrgSpongycastleCryptoDigestsSkeinDigest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

#define RESTRICT_OrgSpongycastleUtilMemoable 1
#define INCLUDE_OrgSpongycastleUtilMemoable 1
#include "org/spongycastle/util/Memoable.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoParamsSkeinParameters;

@interface OrgSpongycastleCryptoDigestsSkeinDigest : NSObject < OrgSpongycastleCryptoExtendedDigest, OrgSpongycastleUtilMemoable >

#pragma mark Public

- (instancetype)initWithInt:(jint)stateSizeBits
                    withInt:(jint)digestSizeBits;

- (instancetype)initWithOrgSpongycastleCryptoDigestsSkeinDigest:(OrgSpongycastleCryptoDigestsSkeinDigest *)digest;

- (id<OrgSpongycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)init__WithOrgSpongycastleCryptoParamsSkeinParameters:(OrgSpongycastleCryptoParamsSkeinParameters *)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)resetWithOrgSpongycastleUtilMemoable:(id<OrgSpongycastleUtilMemoable>)other;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoDigestsSkeinDigest)

inline jint OrgSpongycastleCryptoDigestsSkeinDigest_get_SKEIN_256(void);
#define OrgSpongycastleCryptoDigestsSkeinDigest_SKEIN_256 256
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoDigestsSkeinDigest, SKEIN_256, jint)

inline jint OrgSpongycastleCryptoDigestsSkeinDigest_get_SKEIN_512(void);
#define OrgSpongycastleCryptoDigestsSkeinDigest_SKEIN_512 512
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoDigestsSkeinDigest, SKEIN_512, jint)

inline jint OrgSpongycastleCryptoDigestsSkeinDigest_get_SKEIN_1024(void);
#define OrgSpongycastleCryptoDigestsSkeinDigest_SKEIN_1024 1024
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoDigestsSkeinDigest, SKEIN_1024, jint)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSkeinDigest_initWithInt_withInt_(OrgSpongycastleCryptoDigestsSkeinDigest *self, jint stateSizeBits, jint digestSizeBits);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSkeinDigest *new_OrgSpongycastleCryptoDigestsSkeinDigest_initWithInt_withInt_(jint stateSizeBits, jint digestSizeBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSkeinDigest *create_OrgSpongycastleCryptoDigestsSkeinDigest_initWithInt_withInt_(jint stateSizeBits, jint digestSizeBits);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsSkeinDigest_initWithOrgSpongycastleCryptoDigestsSkeinDigest_(OrgSpongycastleCryptoDigestsSkeinDigest *self, OrgSpongycastleCryptoDigestsSkeinDigest *digest);

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSkeinDigest *new_OrgSpongycastleCryptoDigestsSkeinDigest_initWithOrgSpongycastleCryptoDigestsSkeinDigest_(OrgSpongycastleCryptoDigestsSkeinDigest *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoDigestsSkeinDigest *create_OrgSpongycastleCryptoDigestsSkeinDigest_initWithOrgSpongycastleCryptoDigestsSkeinDigest_(OrgSpongycastleCryptoDigestsSkeinDigest *digest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsSkeinDigest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsSkeinDigest")