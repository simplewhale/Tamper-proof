//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/isismtt/x509/Admissions.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1IsismttX509Admissions")
#ifdef RESTRICT_OrgSpongycastleAsn1IsismttX509Admissions
#define INCLUDE_ALL_OrgSpongycastleAsn1IsismttX509Admissions 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1IsismttX509Admissions 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1IsismttX509Admissions

#if !defined (OrgSpongycastleAsn1IsismttX509Admissions_) && (INCLUDE_ALL_OrgSpongycastleAsn1IsismttX509Admissions || defined(INCLUDE_OrgSpongycastleAsn1IsismttX509Admissions))
#define OrgSpongycastleAsn1IsismttX509Admissions_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1IsismttX509NamingAuthority;
@class OrgSpongycastleAsn1X509GeneralName;

@interface OrgSpongycastleAsn1IsismttX509Admissions : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)admissionAuthority
         withOrgSpongycastleAsn1IsismttX509NamingAuthority:(OrgSpongycastleAsn1IsismttX509NamingAuthority *)namingAuthority
     withOrgSpongycastleAsn1IsismttX509ProfessionInfoArray:(IOSObjectArray *)professionInfos;

- (OrgSpongycastleAsn1X509GeneralName *)getAdmissionAuthority;

+ (OrgSpongycastleAsn1IsismttX509Admissions *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1IsismttX509NamingAuthority *)getNamingAuthority;

- (IOSObjectArray *)getProfessionInfos;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1IsismttX509Admissions)

FOUNDATION_EXPORT OrgSpongycastleAsn1IsismttX509Admissions *OrgSpongycastleAsn1IsismttX509Admissions_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1IsismttX509Admissions_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1IsismttX509NamingAuthority_withOrgSpongycastleAsn1IsismttX509ProfessionInfoArray_(OrgSpongycastleAsn1IsismttX509Admissions *self, OrgSpongycastleAsn1X509GeneralName *admissionAuthority, OrgSpongycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos);

FOUNDATION_EXPORT OrgSpongycastleAsn1IsismttX509Admissions *new_OrgSpongycastleAsn1IsismttX509Admissions_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1IsismttX509NamingAuthority_withOrgSpongycastleAsn1IsismttX509ProfessionInfoArray_(OrgSpongycastleAsn1X509GeneralName *admissionAuthority, OrgSpongycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1IsismttX509Admissions *create_OrgSpongycastleAsn1IsismttX509Admissions_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1IsismttX509NamingAuthority_withOrgSpongycastleAsn1IsismttX509ProfessionInfoArray_(OrgSpongycastleAsn1X509GeneralName *admissionAuthority, OrgSpongycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1IsismttX509Admissions)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1IsismttX509Admissions")
