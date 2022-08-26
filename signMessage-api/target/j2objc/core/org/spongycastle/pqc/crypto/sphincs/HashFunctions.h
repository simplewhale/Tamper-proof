//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/sphincs/HashFunctions.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoSphincsHashFunctions")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoSphincsHashFunctions
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoSphincsHashFunctions 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoSphincsHashFunctions 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoSphincsHashFunctions

#if !defined (OrgSpongycastlePqcCryptoSphincsHashFunctions_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoSphincsHashFunctions || defined(INCLUDE_OrgSpongycastlePqcCryptoSphincsHashFunctions))
#define OrgSpongycastlePqcCryptoSphincsHashFunctions_

@class IOSByteArray;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastlePqcCryptoSphincsHashFunctions : NSObject

#pragma mark Package-Private

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)dig256;

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)dig256
                    withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)dig512;

- (id<OrgSpongycastleCryptoDigest>)getMessageHash;

- (jint)hash_2n_nWithByteArray:(IOSByteArray *)outArg
                       withInt:(jint)outOff
                 withByteArray:(IOSByteArray *)inArg
                       withInt:(jint)inOff;

- (jint)hash_2n_n_maskWithByteArray:(IOSByteArray *)outArg
                            withInt:(jint)outOff
                      withByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                      withByteArray:(IOSByteArray *)mask
                            withInt:(jint)maskOff;

- (jint)hash_n_nWithByteArray:(IOSByteArray *)outArg
                      withInt:(jint)outOff
                withByteArray:(IOSByteArray *)inArg
                      withInt:(jint)inOff;

- (jint)hash_n_n_maskWithByteArray:(IOSByteArray *)outArg
                           withInt:(jint)outOff
                     withByteArray:(IOSByteArray *)inArg
                           withInt:(jint)inOff
                     withByteArray:(IOSByteArray *)mask
                           withInt:(jint)maskOff;

- (jint)varlen_hashWithByteArray:(IOSByteArray *)outArg
                         withInt:(jint)outOff
                   withByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inLen;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastlePqcCryptoSphincsHashFunctions)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_(OrgSpongycastlePqcCryptoSphincsHashFunctions *self, id<OrgSpongycastleCryptoDigest> dig256);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoSphincsHashFunctions *new_OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> dig256) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoSphincsHashFunctions *create_OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> dig256);

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(OrgSpongycastlePqcCryptoSphincsHashFunctions *self, id<OrgSpongycastleCryptoDigest> dig256, id<OrgSpongycastleCryptoDigest> dig512);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoSphincsHashFunctions *new_OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> dig256, id<OrgSpongycastleCryptoDigest> dig512) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoSphincsHashFunctions *create_OrgSpongycastlePqcCryptoSphincsHashFunctions_initWithOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> dig256, id<OrgSpongycastleCryptoDigest> dig512);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoSphincsHashFunctions)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoSphincsHashFunctions")