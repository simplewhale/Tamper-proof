//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/AsymmetricCipherKeyPairGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator")
#ifdef RESTRICT_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator
#define INCLUDE_ALL_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator

#if !defined (OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_) && (INCLUDE_ALL_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator || defined(INCLUDE_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator))
#define OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_

@class OrgSpongycastleCryptoAsymmetricCipherKeyPair;
@class OrgSpongycastleCryptoKeyGenerationParameters;

@protocol OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator < JavaObject >

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator")
