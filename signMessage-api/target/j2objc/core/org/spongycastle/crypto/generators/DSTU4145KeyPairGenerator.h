//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/DSTU4145KeyPairGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator")
#ifdef RESTRICT_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator

#if !defined (OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_) && (INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator || defined(INCLUDE_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator))
#define OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_

#define RESTRICT_OrgSpongycastleCryptoGeneratorsECKeyPairGenerator 1
#define INCLUDE_OrgSpongycastleCryptoGeneratorsECKeyPairGenerator 1
#include "org/spongycastle/crypto/generators/ECKeyPairGenerator.h"

@class OrgSpongycastleCryptoAsymmetricCipherKeyPair;

@interface OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator : OrgSpongycastleCryptoGeneratorsECKeyPairGenerator

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator)

FOUNDATION_EXPORT void OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *new_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *create_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator")
