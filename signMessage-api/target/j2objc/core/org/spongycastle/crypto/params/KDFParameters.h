//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/KDFParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsKDFParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsKDFParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsKDFParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsKDFParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsKDFParameters

#if !defined (OrgSpongycastleCryptoParamsKDFParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsKDFParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsKDFParameters))
#define OrgSpongycastleCryptoParamsKDFParameters_

#define RESTRICT_OrgSpongycastleCryptoDerivationParameters 1
#define INCLUDE_OrgSpongycastleCryptoDerivationParameters 1
#include "org/spongycastle/crypto/DerivationParameters.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoParamsKDFParameters : NSObject < OrgSpongycastleCryptoDerivationParameters > {
 @public
  IOSByteArray *iv_;
  IOSByteArray *shared_;
}

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)shared
                    withByteArray:(IOSByteArray *)iv;

- (IOSByteArray *)getIV;

- (IOSByteArray *)getSharedSecret;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsKDFParameters)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsKDFParameters, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsKDFParameters, shared_, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(OrgSpongycastleCryptoParamsKDFParameters *self, IOSByteArray *shared, IOSByteArray *iv);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsKDFParameters *new_OrgSpongycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(IOSByteArray *shared, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsKDFParameters *create_OrgSpongycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(IOSByteArray *shared, IOSByteArray *iv);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsKDFParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsKDFParameters")
