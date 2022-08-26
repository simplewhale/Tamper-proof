//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/Keccak.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoDigestKeccak
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoDigestKeccak
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest512
#define INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest384
#define INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest288
#define INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest256
#define INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak 1
#endif
#ifdef INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest224
#define INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak 1
#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak))
#define ComYouzhLingtuSignCryptoDigestKeccak_

@interface ComYouzhLingtuSignCryptoDigestKeccak : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak)

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak))
#define ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"

@protocol OrgSpongycastleCryptoDigest;

@interface ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak : ComYouzhLingtuSignCryptoDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype)initWithInt:(jint)size;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak_initWithInt_(ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak *self, jint size);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak *new_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak *create_ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Digest224_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest224))
#define ComYouzhLingtuSignCryptoDigestKeccak_Digest224_

@interface ComYouzhLingtuSignCryptoDigestKeccak_Digest224 : ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Digest224)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Digest224_init(ComYouzhLingtuSignCryptoDigestKeccak_Digest224 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest224 *new_ComYouzhLingtuSignCryptoDigestKeccak_Digest224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest224 *create_ComYouzhLingtuSignCryptoDigestKeccak_Digest224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Digest224)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Digest256_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest256))
#define ComYouzhLingtuSignCryptoDigestKeccak_Digest256_

@interface ComYouzhLingtuSignCryptoDigestKeccak_Digest256 : ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Digest256)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Digest256_init(ComYouzhLingtuSignCryptoDigestKeccak_Digest256 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest256 *new_ComYouzhLingtuSignCryptoDigestKeccak_Digest256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest256 *create_ComYouzhLingtuSignCryptoDigestKeccak_Digest256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Digest256)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Digest288_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest288))
#define ComYouzhLingtuSignCryptoDigestKeccak_Digest288_

@interface ComYouzhLingtuSignCryptoDigestKeccak_Digest288 : ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Digest288)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Digest288_init(ComYouzhLingtuSignCryptoDigestKeccak_Digest288 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest288 *new_ComYouzhLingtuSignCryptoDigestKeccak_Digest288_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest288 *create_ComYouzhLingtuSignCryptoDigestKeccak_Digest288_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Digest288)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Digest384_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest384))
#define ComYouzhLingtuSignCryptoDigestKeccak_Digest384_

@interface ComYouzhLingtuSignCryptoDigestKeccak_Digest384 : ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Digest384)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Digest384_init(ComYouzhLingtuSignCryptoDigestKeccak_Digest384 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest384 *new_ComYouzhLingtuSignCryptoDigestKeccak_Digest384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest384 *create_ComYouzhLingtuSignCryptoDigestKeccak_Digest384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Digest384)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Digest512_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Digest512))
#define ComYouzhLingtuSignCryptoDigestKeccak_Digest512_

@interface ComYouzhLingtuSignCryptoDigestKeccak_Digest512 : ComYouzhLingtuSignCryptoDigestKeccak_DigestKeccak

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Digest512)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Digest512_init(ComYouzhLingtuSignCryptoDigestKeccak_Digest512 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest512 *new_ComYouzhLingtuSignCryptoDigestKeccak_Digest512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Digest512 *create_ComYouzhLingtuSignCryptoDigestKeccak_Digest512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Digest512)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_HashMac224_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_HashMac224))
#define ComYouzhLingtuSignCryptoDigestKeccak_HashMac224_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestKeccak_HashMac224 : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_HashMac224)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_HashMac224_init(ComYouzhLingtuSignCryptoDigestKeccak_HashMac224 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac224 *new_ComYouzhLingtuSignCryptoDigestKeccak_HashMac224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac224 *create_ComYouzhLingtuSignCryptoDigestKeccak_HashMac224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_HashMac224)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_HashMac256_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_HashMac256))
#define ComYouzhLingtuSignCryptoDigestKeccak_HashMac256_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestKeccak_HashMac256 : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_HashMac256)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_HashMac256_init(ComYouzhLingtuSignCryptoDigestKeccak_HashMac256 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac256 *new_ComYouzhLingtuSignCryptoDigestKeccak_HashMac256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac256 *create_ComYouzhLingtuSignCryptoDigestKeccak_HashMac256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_HashMac256)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_HashMac288_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_HashMac288))
#define ComYouzhLingtuSignCryptoDigestKeccak_HashMac288_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestKeccak_HashMac288 : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_HashMac288)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_HashMac288_init(ComYouzhLingtuSignCryptoDigestKeccak_HashMac288 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac288 *new_ComYouzhLingtuSignCryptoDigestKeccak_HashMac288_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac288 *create_ComYouzhLingtuSignCryptoDigestKeccak_HashMac288_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_HashMac288)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_HashMac384_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_HashMac384))
#define ComYouzhLingtuSignCryptoDigestKeccak_HashMac384_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestKeccak_HashMac384 : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_HashMac384)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_HashMac384_init(ComYouzhLingtuSignCryptoDigestKeccak_HashMac384 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac384 *new_ComYouzhLingtuSignCryptoDigestKeccak_HashMac384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac384 *create_ComYouzhLingtuSignCryptoDigestKeccak_HashMac384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_HashMac384)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_HashMac512_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_HashMac512))
#define ComYouzhLingtuSignCryptoDigestKeccak_HashMac512_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestKeccak_HashMac512 : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_HashMac512)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_HashMac512_init(ComYouzhLingtuSignCryptoDigestKeccak_HashMac512 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac512 *new_ComYouzhLingtuSignCryptoDigestKeccak_HashMac512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_HashMac512 *create_ComYouzhLingtuSignCryptoDigestKeccak_HashMac512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_HashMac512)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224))
#define ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224 : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224_init(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224 *new_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224 *create_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator224)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256))
#define ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256 : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256_init(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256 *new_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256 *create_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator256)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288))
#define ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288 : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288_init(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288 *new_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288 *create_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator288)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384))
#define ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384 : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384_init(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384 *new_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384 *create_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator384)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512))
#define ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512 : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512_init(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512 *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512 *new_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512 *create_ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_KeyGenerator512)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestKeccak_Mappings_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestKeccak_Mappings))
#define ComYouzhLingtuSignCryptoDigestKeccak_Mappings_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"

@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;

@interface ComYouzhLingtuSignCryptoDigestKeccak_Mappings : ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype)init;

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoDigestKeccak_Mappings)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestKeccak_Mappings_init(ComYouzhLingtuSignCryptoDigestKeccak_Mappings *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Mappings *new_ComYouzhLingtuSignCryptoDigestKeccak_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestKeccak_Mappings *create_ComYouzhLingtuSignCryptoDigestKeccak_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestKeccak_Mappings)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestKeccak")
