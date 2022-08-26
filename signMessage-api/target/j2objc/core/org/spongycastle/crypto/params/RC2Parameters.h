//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/RC2Parameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsRC2Parameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsRC2Parameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsRC2Parameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsRC2Parameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsRC2Parameters

#if !defined (OrgSpongycastleCryptoParamsRC2Parameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsRC2Parameters || defined(INCLUDE_OrgSpongycastleCryptoParamsRC2Parameters))
#define OrgSpongycastleCryptoParamsRC2Parameters_

#define RESTRICT_OrgSpongycastleCryptoParamsKeyParameter 1
#define INCLUDE_OrgSpongycastleCryptoParamsKeyParameter 1
#include "org/spongycastle/crypto/params/KeyParameter.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoParamsRC2Parameters : OrgSpongycastleCryptoParamsKeyParameter

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)key;

- (instancetype)initWithByteArray:(IOSByteArray *)key
                          withInt:(jint)bits;

- (jint)getEffectiveKeyBits;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithByteArray:(IOSByteArray *)arg0
                          withInt:(jint)arg1
                          withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsRC2Parameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_(OrgSpongycastleCryptoParamsRC2Parameters *self, IOSByteArray *key);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsRC2Parameters *new_OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_(IOSByteArray *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsRC2Parameters *create_OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_(IOSByteArray *key);

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_withInt_(OrgSpongycastleCryptoParamsRC2Parameters *self, IOSByteArray *key, jint bits);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsRC2Parameters *new_OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_withInt_(IOSByteArray *key, jint bits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsRC2Parameters *create_OrgSpongycastleCryptoParamsRC2Parameters_initWithByteArray_withInt_(IOSByteArray *key, jint bits);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsRC2Parameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsRC2Parameters")
