//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/GOST3410KeyGenerationParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters

#if !defined (OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters))
#define OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters_

#define RESTRICT_OrgSpongycastleCryptoKeyGenerationParameters 1
#define INCLUDE_OrgSpongycastleCryptoKeyGenerationParameters 1
#include "org/spongycastle/crypto/KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;
@class OrgSpongycastleCryptoParamsGOST3410Parameters;

@interface OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters : OrgSpongycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
withOrgSpongycastleCryptoParamsGOST3410Parameters:(OrgSpongycastleCryptoParamsGOST3410Parameters *)params;

- (OrgSpongycastleCryptoParamsGOST3410Parameters *)getParameters;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                         withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsGOST3410Parameters_(OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters *self, JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsGOST3410Parameters *params);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters *new_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsGOST3410Parameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsGOST3410Parameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters *create_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsGOST3410Parameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsGOST3410Parameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410KeyGenerationParameters")