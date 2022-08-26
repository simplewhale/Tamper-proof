//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/BaseKeyFactorySpi.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi

#if !defined (ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi))
#define ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi_

#define RESTRICT_JavaSecurityKeyFactorySpi 1
#define INCLUDE_JavaSecurityKeyFactorySpi 1
#include "java/security/KeyFactorySpi.h"

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter 1
#include "com/youzh/lingtu/sign/crypto/utils/AsymmetricKeyInfoConverter.h"

@class IOSClass;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi : JavaSecurityKeyFactorySpi < ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter >

#pragma mark Public

- (instancetype)init;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi_init(ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi *self);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseKeyFactorySpi")
