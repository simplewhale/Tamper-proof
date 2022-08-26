//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/BaseStreamCipher.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher

#if !defined (ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher))
#define ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseWrapCipher 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseWrapCipher 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseWrapCipher.h"

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsPBE 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsPBE 1
#include "com/youzh/lingtu/sign/crypto/utils/PBE.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@protocol JavaSecurityKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol OrgSpongycastleCryptoStreamCipher;
@protocol OrgSpongycastleCryptoWrapper;

@interface ComYouzhLingtuSignCryptoUtilsBaseStreamCipher : ComYouzhLingtuSignCryptoUtilsBaseWrapCipher < ComYouzhLingtuSignCryptoUtilsPBE >

#pragma mark Protected

- (instancetype)initWithOrgSpongycastleCryptoStreamCipher:(id<OrgSpongycastleCryptoStreamCipher>)engine
                                                  withInt:(jint)ivLength;

- (instancetype)initWithOrgSpongycastleCryptoStreamCipher:(id<OrgSpongycastleCryptoStreamCipher>)engine
                                                  withInt:(jint)ivLength
                                                  withInt:(jint)keySizeInBits
                                                  withInt:(jint)digest;

- (IOSByteArray *)engineDoFinalWithByteArray:(IOSByteArray *)input
                                     withInt:(jint)inputOffset
                                     withInt:(jint)inputLen;

- (jint)engineDoFinalWithByteArray:(IOSByteArray *)input
                           withInt:(jint)inputOffset
                           withInt:(jint)inputLen
                     withByteArray:(IOSByteArray *)output
                           withInt:(jint)outputOffset;

- (jint)engineGetBlockSize;

- (IOSByteArray *)engineGetIV;

- (jint)engineGetKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (jint)engineGetOutputSizeWithInt:(jint)inputLen;

- (JavaSecurityAlgorithmParameters *)engineGetParameters;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineSetModeWithNSString:(NSString *)mode;

- (void)engineSetPaddingWithNSString:(NSString *)padding;

- (IOSByteArray *)engineUpdateWithByteArray:(IOSByteArray *)input
                                    withInt:(jint)inputOffset
                                    withInt:(jint)inputLen;

- (jint)engineUpdateWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inputOffset
                          withInt:(jint)inputLen
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outputOffset;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoWrapper:(id<OrgSpongycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoWrapper:(id<OrgSpongycastleCryptoWrapper>)arg0
                                             withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsBaseStreamCipher)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_(ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *self, id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *new_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_(id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *create_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_(id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_withInt_withInt_(ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *self, id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength, jint keySizeInBits, jint digest);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *new_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_withInt_withInt_(id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength, jint keySizeInBits, jint digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsBaseStreamCipher *create_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher_initWithOrgSpongycastleCryptoStreamCipher_withInt_withInt_withInt_(id<OrgSpongycastleCryptoStreamCipher> engine, jint ivLength, jint keySizeInBits, jint digest);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsBaseStreamCipher)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsBaseStreamCipher")