//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/LinuxSecureRandom.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoLinuxSecureRandom")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoLinuxSecureRandom
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoLinuxSecureRandom 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoLinuxSecureRandom 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoLinuxSecureRandom

#if !defined (ComYouzhLingtuSignCryptoLinuxSecureRandom_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoLinuxSecureRandom || defined(INCLUDE_ComYouzhLingtuSignCryptoLinuxSecureRandom))
#define ComYouzhLingtuSignCryptoLinuxSecureRandom_

#define RESTRICT_JavaSecuritySecureRandomSpi 1
#define INCLUDE_JavaSecuritySecureRandomSpi 1
#include "java/security/SecureRandomSpi.h"

@class IOSByteArray;

@interface ComYouzhLingtuSignCryptoLinuxSecureRandom : JavaSecuritySecureRandomSpi

#pragma mark Public

- (instancetype)init;

#pragma mark Protected

- (IOSByteArray *)engineGenerateSeedWithInt:(jint)i;

- (void)engineNextBytesWithByteArray:(IOSByteArray *)bytes;

- (void)engineSetSeedWithByteArray:(IOSByteArray *)bytes;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoLinuxSecureRandom)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoLinuxSecureRandom_init(ComYouzhLingtuSignCryptoLinuxSecureRandom *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoLinuxSecureRandom *new_ComYouzhLingtuSignCryptoLinuxSecureRandom_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoLinuxSecureRandom *create_ComYouzhLingtuSignCryptoLinuxSecureRandom_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoLinuxSecureRandom)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoLinuxSecureRandom")
