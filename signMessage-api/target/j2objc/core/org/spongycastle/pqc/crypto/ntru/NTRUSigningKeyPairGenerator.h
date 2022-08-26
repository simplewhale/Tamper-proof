//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/ntru/NTRUSigningKeyPairGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator

#if !defined (OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator || defined(INCLUDE_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator))
#define OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_

#define RESTRICT_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 1
#define INCLUDE_OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator 1
#include "org/spongycastle/crypto/AsymmetricCipherKeyPairGenerator.h"

@class OrgSpongycastleCryptoAsymmetricCipherKeyPair;
@class OrgSpongycastleCryptoKeyGenerationParameters;
@class OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis;

@interface OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator : NSObject < OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *)generateBoundedBasis;

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPairSingleThread;

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator)

#endif

#if !defined (OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator || defined(INCLUDE_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis))
#define OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_

#define RESTRICT_OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters 1
#define INCLUDE_OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis 1
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningPrivateKeyParameters.h"

@class JavaIoInputStream;
@class OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters;
@class OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator;
@class OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;
@protocol OrgSpongycastlePqcMathNtruPolynomialPolynomial;

@interface OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis : OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis {
 @public
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F_;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G_;
}

#pragma mark Package-Private

- (instancetype)initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *)outer$
                             withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)f
                             withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)fPrime
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)F
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)G
             withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params;

- (jboolean)isNormOk;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)arg1
                              withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)arg0
                    withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)arg1
             withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)arg2
    withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis)

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis, F_, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis, G_, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *self, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator")
