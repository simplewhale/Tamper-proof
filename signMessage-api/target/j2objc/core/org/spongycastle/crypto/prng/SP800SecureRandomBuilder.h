//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/SP800SecureRandomBuilder.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder

#if !defined (OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder || defined(INCLUDE_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder))
#define OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class OrgSpongycastleCryptoPrngSP800SecureRandom;
@protocol OrgSpongycastleCryptoBlockCipher;
@protocol OrgSpongycastleCryptoDigest;
@protocol OrgSpongycastleCryptoMac;
@protocol OrgSpongycastleCryptoPrngEntropySourceProvider;

@interface OrgSpongycastleCryptoPrngSP800SecureRandomBuilder : NSObject

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithOrgSpongycastleCryptoPrngEntropySourceProvider:(id<OrgSpongycastleCryptoPrngEntropySourceProvider>)entropySourceProvider;

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)entropySource
                                     withBoolean:(jboolean)predictionResistant;

- (OrgSpongycastleCryptoPrngSP800SecureRandom *)buildCTRWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                                                                     withInt:(jint)keySizeInBits
                                                                               withByteArray:(IOSByteArray *)nonce
                                                                                 withBoolean:(jboolean)predictionResistant;

- (OrgSpongycastleCryptoPrngSP800SecureRandom *)buildHashWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                                                           withByteArray:(IOSByteArray *)nonce
                                                                             withBoolean:(jboolean)predictionResistant;

- (OrgSpongycastleCryptoPrngSP800SecureRandom *)buildHMACWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)hMac
                                                                        withByteArray:(IOSByteArray *)nonce
                                                                          withBoolean:(jboolean)predictionResistant;

- (OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *)setEntropyBitsRequiredWithInt:(jint)entropyBitsRequired;

- (OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *)setPersonalizationStringWithByteArray:(IOSByteArray *)personalizationString;

- (OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *)setSecurityStrengthWithInt:(jint)securityStrength;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPrngSP800SecureRandomBuilder)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_init(OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *new_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *create_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithJavaSecuritySecureRandom_withBoolean_(OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *self, JavaSecuritySecureRandom *entropySource, jboolean predictionResistant);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *new_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithJavaSecuritySecureRandom_withBoolean_(JavaSecuritySecureRandom *entropySource, jboolean predictionResistant) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *create_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithJavaSecuritySecureRandom_withBoolean_(JavaSecuritySecureRandom *entropySource, jboolean predictionResistant);

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithOrgSpongycastleCryptoPrngEntropySourceProvider_(OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *self, id<OrgSpongycastleCryptoPrngEntropySourceProvider> entropySourceProvider);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *new_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithOrgSpongycastleCryptoPrngEntropySourceProvider_(id<OrgSpongycastleCryptoPrngEntropySourceProvider> entropySourceProvider) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngSP800SecureRandomBuilder *create_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder_initWithOrgSpongycastleCryptoPrngEntropySourceProvider_(id<OrgSpongycastleCryptoPrngEntropySourceProvider> entropySourceProvider);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngSP800SecureRandomBuilder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngSP800SecureRandomBuilder")
