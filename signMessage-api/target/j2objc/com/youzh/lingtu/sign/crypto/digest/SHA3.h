//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/SHA3.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoDigestSHA3
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoDigestSHA3
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest512
#define INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest384
#define INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest256
#define INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest224
#define INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 1
#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3))
#define ComYouzhLingtuSignCryptoDigestSHA3_

@interface ComYouzhLingtuSignCryptoDigestSHA3 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3)

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3))
#define ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"

@protocol OrgSpongycastleCryptoDigest;

@interface ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 : ComYouzhLingtuSignCryptoDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype)initWithInt:(jint)size;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3_initWithInt_(ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 *self, jint size);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 *new_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3 *create_ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_Digest224_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest224))
#define ComYouzhLingtuSignCryptoDigestSHA3_Digest224_

@interface ComYouzhLingtuSignCryptoDigestSHA3_Digest224 : ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_Digest224)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_Digest224_init(ComYouzhLingtuSignCryptoDigestSHA3_Digest224 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest224 *new_ComYouzhLingtuSignCryptoDigestSHA3_Digest224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest224 *create_ComYouzhLingtuSignCryptoDigestSHA3_Digest224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_Digest224)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_Digest256_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest256))
#define ComYouzhLingtuSignCryptoDigestSHA3_Digest256_

@interface ComYouzhLingtuSignCryptoDigestSHA3_Digest256 : ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_Digest256)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_Digest256_init(ComYouzhLingtuSignCryptoDigestSHA3_Digest256 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest256 *new_ComYouzhLingtuSignCryptoDigestSHA3_Digest256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest256 *create_ComYouzhLingtuSignCryptoDigestSHA3_Digest256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_Digest256)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_Digest384_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest384))
#define ComYouzhLingtuSignCryptoDigestSHA3_Digest384_

@interface ComYouzhLingtuSignCryptoDigestSHA3_Digest384 : ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_Digest384)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_Digest384_init(ComYouzhLingtuSignCryptoDigestSHA3_Digest384 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest384 *new_ComYouzhLingtuSignCryptoDigestSHA3_Digest384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest384 *create_ComYouzhLingtuSignCryptoDigestSHA3_Digest384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_Digest384)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_Digest512_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Digest512))
#define ComYouzhLingtuSignCryptoDigestSHA3_Digest512_

@interface ComYouzhLingtuSignCryptoDigestSHA3_Digest512 : ComYouzhLingtuSignCryptoDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_Digest512)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_Digest512_init(ComYouzhLingtuSignCryptoDigestSHA3_Digest512 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest512 *new_ComYouzhLingtuSignCryptoDigestSHA3_Digest512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Digest512 *create_ComYouzhLingtuSignCryptoDigestSHA3_Digest512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_Digest512)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestSHA3_Mappings_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestSHA3_Mappings))
#define ComYouzhLingtuSignCryptoDigestSHA3_Mappings_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"

@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;

@interface ComYouzhLingtuSignCryptoDigestSHA3_Mappings : ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype)init;

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoDigestSHA3_Mappings)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestSHA3_Mappings_init(ComYouzhLingtuSignCryptoDigestSHA3_Mappings *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Mappings *new_ComYouzhLingtuSignCryptoDigestSHA3_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestSHA3_Mappings *create_ComYouzhLingtuSignCryptoDigestSHA3_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestSHA3_Mappings)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestSHA3")