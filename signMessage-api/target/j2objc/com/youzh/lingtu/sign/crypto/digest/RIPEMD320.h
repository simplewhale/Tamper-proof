//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/RIPEMD320.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoDigestRIPEMD320
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoDigestRIPEMD320

#if !defined (ComYouzhLingtuSignCryptoDigestRIPEMD320_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestRIPEMD320))
#define ComYouzhLingtuSignCryptoDigestRIPEMD320_

@interface ComYouzhLingtuSignCryptoDigestRIPEMD320 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestRIPEMD320)

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestRIPEMD320)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest))
#define ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"

@protocol OrgSpongycastleCryptoDigest;

@interface ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest : ComYouzhLingtuSignCryptoDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest_init(ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest *new_ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest *create_ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestRIPEMD320_Digest)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac))
#define ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac_init(ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac *new_ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac *create_ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestRIPEMD320_HashMac)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator))
#define ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator_init(ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator *new_ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator *create_ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestRIPEMD320_KeyGenerator)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320 || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings))
#define ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"

@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;

@interface ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings : ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype)init;

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings_init(ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings *new_ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings *create_ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestRIPEMD320_Mappings)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestRIPEMD320")