//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/ParametersWithIV.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsParametersWithIV")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsParametersWithIV
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsParametersWithIV 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsParametersWithIV 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsParametersWithIV

#if !defined (OrgSpongycastleCryptoParamsParametersWithIV_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsParametersWithIV || defined(INCLUDE_OrgSpongycastleCryptoParamsParametersWithIV))
#define OrgSpongycastleCryptoParamsParametersWithIV_

#define RESTRICT_OrgSpongycastleCryptoCipherParameters 1
#define INCLUDE_OrgSpongycastleCryptoCipherParameters 1
#include "org/spongycastle/crypto/CipherParameters.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoParamsParametersWithIV : NSObject < OrgSpongycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters
                                                withByteArray:(IOSByteArray *)iv;

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters
                                                withByteArray:(IOSByteArray *)iv
                                                      withInt:(jint)ivOff
                                                      withInt:(jint)ivLen;

- (IOSByteArray *)getIV;

- (id<OrgSpongycastleCryptoCipherParameters>)getParameters;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsParametersWithIV)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(OrgSpongycastleCryptoParamsParametersWithIV *self, id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsParametersWithIV *new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsParametersWithIV *create_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv);

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(OrgSpongycastleCryptoParamsParametersWithIV *self, id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsParametersWithIV *new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsParametersWithIV *create_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsParametersWithIV)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsParametersWithIV")