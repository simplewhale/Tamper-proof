//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/AsymmetricKeyInfoConverter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter

#if !defined (ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter))
#define ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter_

@class OrgSpongycastleAsn1PkcsPrivateKeyInfo;
@class OrgSpongycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@protocol ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter < JavaObject >

- (id<JavaSecurityPrivateKey>)generatePrivateWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (id<JavaSecurityPublicKey>)generatePublicWithOrgSpongycastleAsn1X509SubjectPublicKeyInfo:(OrgSpongycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter)

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsAsymmetricKeyInfoConverter")
