//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/NaccacheSternKeyGenerationParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters

#if !defined (OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters))
#define OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_

#define RESTRICT_OrgSpongycastleCryptoKeyGenerationParameters 1
#define INCLUDE_OrgSpongycastleCryptoKeyGenerationParameters 1
#include "org/spongycastle/crypto/KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;

@interface OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters : OrgSpongycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                         withInt:(jint)strength
                                         withInt:(jint)certainty
                                         withInt:(jint)cntSmallPrimes;

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                         withInt:(jint)strength
                                         withInt:(jint)certainty
                                         withInt:(jint)cntSmallPrimes
                                     withBoolean:(jboolean)debug;

- (jint)getCertainty;

- (jint)getCntSmallPrimes;

- (jboolean)isDebug;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                         withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_(OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *self, JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *new_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_(JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *create_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_(JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes);

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_withBoolean_(OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *self, JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes, jboolean debug);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *new_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_withBoolean_(JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes, jboolean debug) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters *create_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_withInt_withInt_withBoolean_(JavaSecuritySecureRandom *random, jint strength, jint certainty, jint cntSmallPrimes, jboolean debug);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternKeyGenerationParameters")