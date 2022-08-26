//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSPublicKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters))
#define OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#define INCLUDE_OrgSpongycastleCryptoParamsAsymmetricKeyParameter 1
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"

#define RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface 1
#define INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface 1
#include "org/spongycastle/pqc/crypto/xmss/XMSSStoreableObjectInterface.h"

@class IOSByteArray;
@class OrgSpongycastlePqcCryptoXmssXMSSParameters;

@interface OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters : OrgSpongycastleCryptoParamsAsymmetricKeyParameter < OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface >

#pragma mark Public

- (OrgSpongycastlePqcCryptoXmssXMSSParameters *)getParameters;

- (IOSByteArray *)getPublicSeed;

- (IOSByteArray *)getRoot;

- (IOSByteArray *)toByteArray;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters)

#endif

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder))
#define OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_

@class IOSByteArray;
@class OrgSpongycastlePqcCryptoXmssXMSSParameters;
@class OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters;

@interface OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSParameters:(OrgSpongycastlePqcCryptoXmssXMSSParameters *)params;

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *)build;

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicKeyWithByteArray:(IOSByteArray *)val;

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicSeedWithByteArray:(IOSByteArray *)val;

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withRootWithByteArray:(IOSByteArray *)val;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *self, OrgSpongycastlePqcCryptoXmssXMSSParameters *params);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *new_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *create_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters")
