//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/GOST3411_2012Digest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsGOST3411_2012Digest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsGOST3411_2012Digest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsGOST3411_2012Digest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsGOST3411_2012Digest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsGOST3411_2012Digest

#if !defined (OrgSpongycastleCryptoDigestsGOST3411_2012Digest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsGOST3411_2012Digest || defined(INCLUDE_OrgSpongycastleCryptoDigestsGOST3411_2012Digest))
#define OrgSpongycastleCryptoDigestsGOST3411_2012Digest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

#define RESTRICT_OrgSpongycastleUtilMemoable 1
#define INCLUDE_OrgSpongycastleUtilMemoable 1
#include "org/spongycastle/util/Memoable.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsGOST3411_2012Digest : NSObject < OrgSpongycastleCryptoExtendedDigest, OrgSpongycastleUtilMemoable >

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)IV;

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

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoDigestsGOST3411_2012Digest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsGOST3411_2012Digest_initWithByteArray_(OrgSpongycastleCryptoDigestsGOST3411_2012Digest *self, IOSByteArray *IV);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsGOST3411_2012Digest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsGOST3411_2012Digest")
