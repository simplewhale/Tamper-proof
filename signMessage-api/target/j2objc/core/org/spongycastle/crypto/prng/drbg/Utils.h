//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/drbg/Utils.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgUtils")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngDrbgUtils
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgUtils 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgUtils 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngDrbgUtils

#if !defined (OrgSpongycastleCryptoPrngDrbgUtils_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgUtils || defined(INCLUDE_OrgSpongycastleCryptoPrngDrbgUtils))
#define OrgSpongycastleCryptoPrngDrbgUtils_

@class IOSByteArray;
@class JavaUtilHashtable;
@protocol OrgSpongycastleCryptoDigest;
@protocol OrgSpongycastleCryptoMac;

@interface OrgSpongycastleCryptoPrngDrbgUtils : NSObject

#pragma mark Package-Private

- (instancetype)init;

+ (jint)getMaxSecurityStrengthWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)d;

+ (jint)getMaxSecurityStrengthWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)m;

+ (IOSByteArray *)hash_dfWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                           withByteArray:(IOSByteArray *)seedMaterial
                                                 withInt:(jint)seedLength;

+ (jboolean)isTooLargeWithByteArray:(IOSByteArray *)bytes
                            withInt:(jint)maxBytes;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoPrngDrbgUtils)

inline JavaUtilHashtable *OrgSpongycastleCryptoPrngDrbgUtils_get_maxSecurityStrengths(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleCryptoPrngDrbgUtils_maxSecurityStrengths;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgUtils, maxSecurityStrengths, JavaUtilHashtable *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngDrbgUtils_init(OrgSpongycastleCryptoPrngDrbgUtils *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngDrbgUtils *new_OrgSpongycastleCryptoPrngDrbgUtils_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngDrbgUtils *create_OrgSpongycastleCryptoPrngDrbgUtils_init(void);

FOUNDATION_EXPORT jint OrgSpongycastleCryptoPrngDrbgUtils_getMaxSecurityStrengthWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> d);

FOUNDATION_EXPORT jint OrgSpongycastleCryptoPrngDrbgUtils_getMaxSecurityStrengthWithOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoMac> m);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleCryptoPrngDrbgUtils_hash_dfWithOrgSpongycastleCryptoDigest_withByteArray_withInt_(id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *seedMaterial, jint seedLength);

FOUNDATION_EXPORT jboolean OrgSpongycastleCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(IOSByteArray *bytes, jint maxBytes);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngDrbgUtils)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgUtils")
