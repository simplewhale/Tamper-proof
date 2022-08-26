//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DHKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDHKeyParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsDHKeyParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDHKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDHKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsDHKeyParameters

#if !defined (OrgSpongycastleCryptoParamsDHKeyParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsDHKeyParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsDHKeyParameters))
#define OrgSpongycastleCryptoParamsDHKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#define INCLUDE_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"

@class OrgSpongycastleCryptoParamsDHParameters;

@interface OrgSpongycastleCryptoParamsDHKeyParameters : OrgSpongycastleCryptoParamsAsymmetricKeyParameter

#pragma mark Public

- (jboolean)isEqual:(id)obj;

- (OrgSpongycastleCryptoParamsDHParameters *)getParameters;

- (NSUInteger)hash;

#pragma mark Protected

- (instancetype)initWithBoolean:(jboolean)isPrivate
withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)params;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsDHKeyParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsDHKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoParamsDHKeyParameters *self, jboolean isPrivate, OrgSpongycastleCryptoParamsDHParameters *params);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDHKeyParameters *new_OrgSpongycastleCryptoParamsDHKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDHParameters_(jboolean isPrivate, OrgSpongycastleCryptoParamsDHParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDHKeyParameters *create_OrgSpongycastleCryptoParamsDHKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDHParameters_(jboolean isPrivate, OrgSpongycastleCryptoParamsDHParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsDHKeyParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDHKeyParameters")
