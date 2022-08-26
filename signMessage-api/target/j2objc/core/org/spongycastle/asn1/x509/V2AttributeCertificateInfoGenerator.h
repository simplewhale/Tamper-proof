//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/V2AttributeCertificateInfoGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator")
#ifdef RESTRICT_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator
#define INCLUDE_ALL_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator

#if !defined (OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator || defined(INCLUDE_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator))
#define OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator_

@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1DERBitString;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@class OrgSpongycastleAsn1X509AttCertIssuer;
@class OrgSpongycastleAsn1X509Attribute;
@class OrgSpongycastleAsn1X509AttributeCertificateInfo;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509Holder;
@class OrgSpongycastleAsn1X509X509Extensions;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator : NSObject

#pragma mark Public

- (instancetype)init;

- (void)addAttributeWithOrgSpongycastleAsn1X509Attribute:(OrgSpongycastleAsn1X509Attribute *)attribute;

- (void)addAttributeWithNSString:(NSString *)oid
withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)value;

- (OrgSpongycastleAsn1X509AttributeCertificateInfo *)generateAttributeCertificateInfo;

- (void)setEndDateWithOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)endDate;

- (void)setExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

- (void)setExtensionsWithOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)extensions;

- (void)setHolderWithOrgSpongycastleAsn1X509Holder:(OrgSpongycastleAsn1X509Holder *)holder;

- (void)setIssuerWithOrgSpongycastleAsn1X509AttCertIssuer:(OrgSpongycastleAsn1X509AttCertIssuer *)issuer;

- (void)setIssuerUniqueIDWithOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)issuerUniqueID;

- (void)setSerialNumberWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)serialNumber;

- (void)setSignatureWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)signature;

- (void)setStartDateWithOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)startDate;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator_init(OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator *new_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator *create_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509V2AttributeCertificateInfoGenerator")
