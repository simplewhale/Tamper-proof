//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider

#if !defined (ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider || defined(INCLUDE_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider))
#define ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/utils/AlgorithmProvider.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;

@interface ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider : ComYouzhLingtuSignCryptoUtilsAlgorithmProvider

#pragma mark Protected

- (void)addHMACAlgorithmWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider
                                                                  withNSString:(NSString *)algorithm
                                                                  withNSString:(NSString *)algorithmClassName
                                                                  withNSString:(NSString *)keyGeneratorClassName;

- (void)addHMACAliasWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider
                                                              withNSString:(NSString *)algorithm
                               withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

#pragma mark Package-Private

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_init(ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider *self);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider")