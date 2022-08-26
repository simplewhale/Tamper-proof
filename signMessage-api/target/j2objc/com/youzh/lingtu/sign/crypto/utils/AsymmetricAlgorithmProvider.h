//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/AsymmetricAlgorithmProvider.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider

#if !defined (ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider))
#define ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsAlgorithmProvider 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsAlgorithmProvider 1
#include "com/youzh/lingtu/sign/crypto/utils/AlgorithmProvider.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@protocol ComYouzhLingtuSignCryptoConfigConfigurableProvider;
@protocol ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter;

@interface ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider : ComYouzhLingtuSignCryptoUtilsAlgorithmProvider

#pragma mark Public

- (instancetype)init;

#pragma mark Protected

- (void)addSignatureAlgorithmWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider
                                                                       withNSString:(NSString *)digest
                                                                       withNSString:(NSString *)algorithm
                                                                       withNSString:(NSString *)className_
                                        withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (void)registerOidWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider
                              withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                                                             withNSString:(NSString *)name
              withComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter:(id<ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter>)keyFactory;

- (void)registerOidAlgorithmParametersWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider
                                                 withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                withNSString:(NSString *)name;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider_init(ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider *self);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricAlgorithmProvider")