//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/Tiger.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoDigestTiger
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoDigestTiger

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger))
#define ComYouzhLingtuSignCryptoDigestTiger_

@interface ComYouzhLingtuSignCryptoDigestTiger : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger)

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_Digest_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_Digest))
#define ComYouzhLingtuSignCryptoDigestTiger_Digest_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestBCMessageDigest 1
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"

@protocol OrgSpongycastleCryptoDigest;

@interface ComYouzhLingtuSignCryptoDigestTiger_Digest : ComYouzhLingtuSignCryptoDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_Digest)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_Digest_init(ComYouzhLingtuSignCryptoDigestTiger_Digest *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_Digest *new_ComYouzhLingtuSignCryptoDigestTiger_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_Digest *create_ComYouzhLingtuSignCryptoDigestTiger_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_Digest)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_HashMac_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_HashMac))
#define ComYouzhLingtuSignCryptoDigestTiger_HashMac_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestTiger_HashMac : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_HashMac)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_HashMac_init(ComYouzhLingtuSignCryptoDigestTiger_HashMac *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_HashMac *new_ComYouzhLingtuSignCryptoDigestTiger_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_HashMac *create_ComYouzhLingtuSignCryptoDigestTiger_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_HashMac)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator))
#define ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"

@class OrgSpongycastleCryptoCipherKeyGenerator;

@interface ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator : ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                         withInt:(jint)arg1
withOrgSpongycastleCryptoCipherKeyGenerator:(OrgSpongycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator_init(ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator *new_ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator *create_ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_KeyGenerator)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_TigerHmac_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_TigerHmac))
#define ComYouzhLingtuSignCryptoDigestTiger_TigerHmac_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestTiger_TigerHmac : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_TigerHmac)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_TigerHmac_init(ComYouzhLingtuSignCryptoDigestTiger_TigerHmac *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_TigerHmac *new_ComYouzhLingtuSignCryptoDigestTiger_TigerHmac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_TigerHmac *create_ComYouzhLingtuSignCryptoDigestTiger_TigerHmac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_TigerHmac)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory))
#define ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsPBESecretKeyFactory 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsPBESecretKeyFactory 1
#include "com/youzh/lingtu/sign/crypto/utils/PBESecretKeyFactory.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;

@interface ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory : ComYouzhLingtuSignCryptoUtilsPBESecretKeyFactory

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)arg1
                     withBoolean:(jboolean)arg2
                         withInt:(jint)arg3
                         withInt:(jint)arg4
                         withInt:(jint)arg5
                         withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory_init(ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory *new_ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory *create_ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_PBEWithMacKeyFactory)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac))
#define ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsBaseMac 1
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"

@protocol OrgSpongycastleCryptoMac;

@interface ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac : ComYouzhLingtuSignCryptoUtilsBaseMac

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)arg0
                                         withInt:(jint)arg1
                                         withInt:(jint)arg2
                                         withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac_init(ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac *new_ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac *create_ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_PBEWithHashMac)

#endif

#if !defined (ComYouzhLingtuSignCryptoDigestTiger_Mappings_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestTiger_Mappings))
#define ComYouzhLingtuSignCryptoDigestTiger_Mappings_

#define RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"

@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;

@interface ComYouzhLingtuSignCryptoDigestTiger_Mappings : ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype)init;

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoDigestTiger_Mappings)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestTiger_Mappings_init(ComYouzhLingtuSignCryptoDigestTiger_Mappings *self);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_Mappings *new_ComYouzhLingtuSignCryptoDigestTiger_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoDigestTiger_Mappings *create_ComYouzhLingtuSignCryptoDigestTiger_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestTiger_Mappings)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestTiger")