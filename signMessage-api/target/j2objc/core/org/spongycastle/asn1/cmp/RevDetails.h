//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/RevDetails.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpRevDetails")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpRevDetails
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpRevDetails 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpRevDetails 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpRevDetails

#if !defined (OrgSpongycastleAsn1CmpRevDetails_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpRevDetails || defined(INCLUDE_OrgSpongycastleAsn1CmpRevDetails))
#define OrgSpongycastleAsn1CmpRevDetails_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CrmfCertTemplate;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509X509Extensions;

@interface OrgSpongycastleAsn1CmpRevDetails : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CrmfCertTemplate:(OrgSpongycastleAsn1CrmfCertTemplate *)certDetails;

- (instancetype)initWithOrgSpongycastleAsn1CrmfCertTemplate:(OrgSpongycastleAsn1CrmfCertTemplate *)certDetails
                      withOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)crlEntryDetails;

- (instancetype)initWithOrgSpongycastleAsn1CrmfCertTemplate:(OrgSpongycastleAsn1CrmfCertTemplate *)certDetails
                  withOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)crlEntryDetails;

- (OrgSpongycastleAsn1CrmfCertTemplate *)getCertDetails;

- (OrgSpongycastleAsn1X509Extensions *)getCrlEntryDetails;

+ (OrgSpongycastleAsn1CmpRevDetails *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmpRevDetails)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *OrgSpongycastleAsn1CmpRevDetails_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_(OrgSpongycastleAsn1CmpRevDetails *self, OrgSpongycastleAsn1CrmfCertTemplate *certDetails);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *new_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *create_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1CmpRevDetails *self, OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509X509Extensions *crlEntryDetails);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *new_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509X509Extensions *crlEntryDetails) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *create_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509X509Extensions *crlEntryDetails);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1CmpRevDetails *self, OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509Extensions *crlEntryDetails);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *new_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509Extensions *crlEntryDetails) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpRevDetails *create_OrgSpongycastleAsn1CmpRevDetails_initWithOrgSpongycastleAsn1CrmfCertTemplate_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1CrmfCertTemplate *certDetails, OrgSpongycastleAsn1X509Extensions *crlEntryDetails);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpRevDetails)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpRevDetails")
