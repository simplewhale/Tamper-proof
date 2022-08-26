//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/DSAKeyPairGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator")
#ifdef RESTRICT_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator

#if !defined (OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator_) && (INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator || defined(INCLUDE_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator))
#define OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator_

#define RESTRICT_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 1
#define INCLUDE_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 1
#include "org/spongycastle/crypto/AsymmetricCipherKeyPairGenerator.h"

@class OrgSpongycastleCryptoAsymmetricCipherKeyPair;
@class OrgSpongycastleCryptoKeyGenerationParameters;

@interface OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator : NSObject < OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator)

FOUNDATION_EXPORT void OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator_init(OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator *new_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator *create_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSAKeyPairGenerator")