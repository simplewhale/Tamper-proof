//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/PKCS12ParametersGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator")
#ifdef RESTRICT_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator

#if !defined (OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_) && (INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator || defined(INCLUDE_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator))
#define OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_

#define RESTRICT_OrgSpongycastleCryptoPBEParametersGenerator 1
#define INCLUDE_OrgSpongycastleCryptoPBEParametersGenerator 1
#include "org/spongycastle/crypto/PBEParametersGenerator.h"

@protocol OrgSpongycastleCryptoCipherParameters;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator : OrgSpongycastleCryptoPBEParametersGenerator

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize;

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize;

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                      withInt:(jint)ivSize;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator)

inline jint OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_get_KEY_MATERIAL(void);
#define OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator, KEY_MATERIAL, jint)

inline jint OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_get_IV_MATERIAL(void);
#define OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_IV_MATERIAL 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator, IV_MATERIAL, jint)

inline jint OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_get_MAC_MATERIAL(void);
#define OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_MAC_MATERIAL 3
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator, MAC_MATERIAL, jint)

FOUNDATION_EXPORT void OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator *self, id<OrgSpongycastleCryptoDigest> digest);

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator *new_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator *create_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsPKCS12ParametersGenerator")
