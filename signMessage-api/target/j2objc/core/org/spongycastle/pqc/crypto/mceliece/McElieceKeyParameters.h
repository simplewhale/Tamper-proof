//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/mceliece/McElieceKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters

#if !defined (OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters || defined(INCLUDE_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters))
#define OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#define INCLUDE_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"

@class OrgSpongycastlePqcCryptoMcelieceMcElieceParameters;

@interface OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters : OrgSpongycastleCryptoParamsAsymmetricKeyParameter

#pragma mark Public

- (instancetype)initWithBoolean:(jboolean)isPrivate
withOrgSpongycastlePqcCryptoMcelieceMcElieceParameters:(OrgSpongycastlePqcCryptoMcelieceMcElieceParameters *)params;

- (OrgSpongycastlePqcCryptoMcelieceMcElieceParameters *)getParameters;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoMcelieceMcElieceParameters_(OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters *self, jboolean isPrivate, OrgSpongycastlePqcCryptoMcelieceMcElieceParameters *params);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters *new_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoMcelieceMcElieceParameters_(jboolean isPrivate, OrgSpongycastlePqcCryptoMcelieceMcElieceParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters *create_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoMcelieceMcElieceParameters_(jboolean isPrivate, OrgSpongycastlePqcCryptoMcelieceMcElieceParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters")
