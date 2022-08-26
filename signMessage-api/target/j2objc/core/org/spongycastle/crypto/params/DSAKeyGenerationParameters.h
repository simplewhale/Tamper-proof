//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DSAKeyGenerationParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters

#if !defined (OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters))
#define OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_

#define RESTRICT_OrgSpongycastleCryptoKeyGenerationParameters 1
#define INCLUDE_OrgSpongycastleCryptoKeyGenerationParameters 1
#include "org/spongycastle/crypto/KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;
@class OrgSpongycastleCryptoParamsDSAParameters;

@interface OrgSpongycastleCryptoParamsDSAKeyGenerationParameters : OrgSpongycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
    withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params;

- (OrgSpongycastleCryptoParamsDSAParameters *)getParameters;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                         withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *self, JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *new_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *create_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters")
