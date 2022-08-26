//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DSAValidationParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAValidationParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsDSAValidationParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAValidationParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAValidationParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsDSAValidationParameters

#if !defined (OrgSpongycastleCryptoParamsDSAValidationParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAValidationParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsDSAValidationParameters))
#define OrgSpongycastleCryptoParamsDSAValidationParameters_

@class IOSByteArray;

@interface OrgSpongycastleCryptoParamsDSAValidationParameters : NSObject

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)seed
                          withInt:(jint)counter;

- (instancetype)initWithByteArray:(IOSByteArray *)seed
                          withInt:(jint)counter
                          withInt:(jint)usageIndex;

- (jboolean)isEqual:(id)o;

- (jint)getCounter;

- (IOSByteArray *)getSeed;

- (jint)getUsageIndex;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsDSAValidationParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_(OrgSpongycastleCryptoParamsDSAValidationParameters *self, IOSByteArray *seed, jint counter);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAValidationParameters *new_OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAValidationParameters *create_OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter);

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_withInt_(OrgSpongycastleCryptoParamsDSAValidationParameters *self, IOSByteArray *seed, jint counter, jint usageIndex);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAValidationParameters *new_OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_withInt_(IOSByteArray *seed, jint counter, jint usageIndex) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAValidationParameters *create_OrgSpongycastleCryptoParamsDSAValidationParameters_initWithByteArray_withInt_withInt_(IOSByteArray *seed, jint counter, jint usageIndex);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsDSAValidationParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAValidationParameters")