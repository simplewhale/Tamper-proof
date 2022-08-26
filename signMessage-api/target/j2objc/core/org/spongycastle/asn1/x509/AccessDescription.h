//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/AccessDescription.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509AccessDescription")
#ifdef RESTRICT_OrgSpongycastleAsn1X509AccessDescription
#define INCLUDE_ALL_OrgSpongycastleAsn1X509AccessDescription 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509AccessDescription 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509AccessDescription

#if !defined (OrgSpongycastleAsn1X509AccessDescription_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509AccessDescription || defined(INCLUDE_OrgSpongycastleAsn1X509AccessDescription))
#define OrgSpongycastleAsn1X509AccessDescription_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509GeneralName;

@interface OrgSpongycastleAsn1X509AccessDescription : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *accessMethod_;
  OrgSpongycastleAsn1X509GeneralName *accessLocation_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                         withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)location;

- (OrgSpongycastleAsn1X509GeneralName *)getAccessLocation;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getAccessMethod;

+ (OrgSpongycastleAsn1X509AccessDescription *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1X509AccessDescription)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509AccessDescription, accessMethod_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509AccessDescription, accessLocation_, OrgSpongycastleAsn1X509GeneralName *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509AccessDescription_get_id_ad_caIssuers(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509AccessDescription_id_ad_caIssuers;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509AccessDescription, id_ad_caIssuers, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509AccessDescription_get_id_ad_ocsp(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509AccessDescription_id_ad_ocsp;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509AccessDescription, id_ad_ocsp, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509AccessDescription *OrgSpongycastleAsn1X509AccessDescription_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509AccessDescription_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1X509AccessDescription *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, OrgSpongycastleAsn1X509GeneralName *location);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509AccessDescription *new_OrgSpongycastleAsn1X509AccessDescription_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, OrgSpongycastleAsn1X509GeneralName *location) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509AccessDescription *create_OrgSpongycastleAsn1X509AccessDescription_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, OrgSpongycastleAsn1X509GeneralName *location);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509AccessDescription)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509AccessDescription")