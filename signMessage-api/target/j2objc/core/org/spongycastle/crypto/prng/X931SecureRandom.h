//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/X931SecureRandom.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngX931SecureRandom")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngX931SecureRandom
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngX931SecureRandom 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngX931SecureRandom 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngX931SecureRandom

#if !defined (OrgSpongycastleCryptoPrngX931SecureRandom_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngX931SecureRandom || defined(INCLUDE_OrgSpongycastleCryptoPrngX931SecureRandom))
#define OrgSpongycastleCryptoPrngX931SecureRandom_

#define RESTRICT_JavaSecuritySecureRandom 1
#define INCLUDE_JavaSecuritySecureRandom 1
#include "java/security/SecureRandom.h"

@class IOSByteArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandomSpi;
@class OrgSpongycastleCryptoPrngX931RNG;

@interface OrgSpongycastleCryptoPrngX931SecureRandom : JavaSecuritySecureRandom

#pragma mark Public

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

- (void)setSeedWithByteArray:(IOSByteArray *)seed;

- (void)setSeedWithLong:(jlong)seed;

#pragma mark Package-Private

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)randomSource
            withOrgSpongycastleCryptoPrngX931RNG:(OrgSpongycastleCryptoPrngX931RNG *)drbg
                                     withBoolean:(jboolean)predictionResistant;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype)initWithJavaSecuritySecureRandomSpi:(JavaSecuritySecureRandomSpi *)arg0
                           withJavaSecurityProvider:(JavaSecurityProvider *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPrngX931SecureRandom)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoPrngX931RNG_withBoolean_(OrgSpongycastleCryptoPrngX931SecureRandom *self, JavaSecuritySecureRandom *randomSource, OrgSpongycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngX931SecureRandom *new_OrgSpongycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoPrngX931RNG_withBoolean_(JavaSecuritySecureRandom *randomSource, OrgSpongycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngX931SecureRandom *create_OrgSpongycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoPrngX931RNG_withBoolean_(JavaSecuritySecureRandom *randomSource, OrgSpongycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngX931SecureRandom)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngX931SecureRandom")