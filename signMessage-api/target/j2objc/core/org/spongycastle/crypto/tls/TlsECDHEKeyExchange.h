//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsECDHEKeyExchange.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange

#if !defined (OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange))
#define OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_

#define RESTRICT_OrgSpongycastleCryptoTlsTlsECDHKeyExchange 1
#define INCLUDE_OrgSpongycastleCryptoTlsTlsECDHKeyExchange 1
#include "org/spongycastle/crypto/tls/TlsECDHKeyExchange.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;
@class JavaIoInputStream;
@class JavaUtilVector;
@class OrgSpongycastleCryptoTlsCertificateRequest;
@class OrgSpongycastleCryptoTlsSecurityParameters;
@class OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;
@protocol OrgSpongycastleCryptoSigner;
@protocol OrgSpongycastleCryptoTlsTlsCredentials;
@protocol OrgSpongycastleCryptoTlsTlsSigner;
@protocol OrgSpongycastleCryptoTlsTlsSignerCredentials;

@interface OrgSpongycastleCryptoTlsTlsECDHEKeyExchange : OrgSpongycastleCryptoTlsTlsECDHKeyExchange {
 @public
  id<OrgSpongycastleCryptoTlsTlsSignerCredentials> serverCredentials_;
}

#pragma mark Public

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
               withIntArray:(IOSIntArray *)namedCurves
             withShortArray:(IOSShortArray *)clientECPointFormats
             withShortArray:(IOSShortArray *)serverECPointFormats;

- (IOSByteArray *)generateServerKeyExchange;

- (void)processClientCredentialsWithOrgSpongycastleCryptoTlsTlsCredentials:(id<OrgSpongycastleCryptoTlsTlsCredentials>)clientCredentials;

- (void)processServerCredentialsWithOrgSpongycastleCryptoTlsTlsCredentials:(id<OrgSpongycastleCryptoTlsTlsCredentials>)serverCredentials;

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input;

- (void)validateCertificateRequestWithOrgSpongycastleCryptoTlsCertificateRequest:(OrgSpongycastleCryptoTlsCertificateRequest *)certificateRequest;

#pragma mark Protected

- (id<OrgSpongycastleCryptoSigner>)initVerifyerWithOrgSpongycastleCryptoTlsTlsSigner:(id<OrgSpongycastleCryptoTlsTlsSigner>)tlsSigner
                               withOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                      withOrgSpongycastleCryptoTlsSecurityParameters:(OrgSpongycastleCryptoTlsSecurityParameters *)securityParameters OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsECDHEKeyExchange)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsTlsECDHEKeyExchange, serverCredentials_, id<OrgSpongycastleCryptoTlsTlsSignerCredentials>)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(OrgSpongycastleCryptoTlsTlsECDHEKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsECDHEKeyExchange *new_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsECDHEKeyExchange *create_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsECDHEKeyExchange)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange")
