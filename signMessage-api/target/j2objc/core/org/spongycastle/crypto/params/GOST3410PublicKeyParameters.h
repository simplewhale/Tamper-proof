//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/GOST3410PublicKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters

#if !defined (OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters))
#define OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsGOST3410KeyParameters 1
#define INCLUDE_OrgSpongycastleCryptoParamsGOST3410KeyParameters 1
#include "org/spongycastle/crypto/params/GOST3410KeyParameters.h"

@class JavaMathBigInteger;
@class OrgSpongycastleCryptoParamsGOST3410Parameters;

@interface OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters : OrgSpongycastleCryptoParamsGOST3410KeyParameters

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
withOrgSpongycastleCryptoParamsGOST3410Parameters:(OrgSpongycastleCryptoParamsGOST3410Parameters *)params;

- (JavaMathBigInteger *)getY;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0
withOrgSpongycastleCryptoParamsGOST3410Parameters:(OrgSpongycastleCryptoParamsGOST3410Parameters *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410Parameters_(OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsGOST3410Parameters *params);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters *new_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410Parameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsGOST3410Parameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters *create_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410Parameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsGOST3410Parameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410PublicKeyParameters")