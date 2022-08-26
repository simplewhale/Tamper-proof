//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/newhope/NHPrivateKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters

#if !defined (OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters || defined(INCLUDE_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters))
#define OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#define INCLUDE_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"

@class IOSShortArray;

@interface OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters : OrgSpongycastleCryptoParamsAsymmetricKeyParameter {
 @public
  IOSShortArray *secData_;
}

#pragma mark Public

- (instancetype)initWithShortArray:(IOSShortArray *)secData;

- (IOSShortArray *)getSecData;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters)

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters, secData_, IOSShortArray *)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *self, IOSShortArray *secData);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *new_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *create_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters")
