//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/est/AttrOrOID.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EstAttrOrOID")
#ifdef RESTRICT_OrgSpongycastleAsn1EstAttrOrOID
#define INCLUDE_ALL_OrgSpongycastleAsn1EstAttrOrOID 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EstAttrOrOID 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EstAttrOrOID

#if !defined (OrgSpongycastleAsn1EstAttrOrOID_) && (INCLUDE_ALL_OrgSpongycastleAsn1EstAttrOrOID || defined(INCLUDE_OrgSpongycastleAsn1EstAttrOrOID))
#define OrgSpongycastleAsn1EstAttrOrOID_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1Choice 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Choice 1
#include "org/spongycastle/asn1/ASN1Choice.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1PkcsAttribute;

@interface OrgSpongycastleAsn1EstAttrOrOID : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (instancetype)initWithOrgSpongycastleAsn1PkcsAttribute:(OrgSpongycastleAsn1PkcsAttribute *)attribute;

- (OrgSpongycastleAsn1PkcsAttribute *)getAttribute;

+ (OrgSpongycastleAsn1EstAttrOrOID *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getOid;

- (jboolean)isOid;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EstAttrOrOID)

FOUNDATION_EXPORT void OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1EstAttrOrOID *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstAttrOrOID *new_OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EstAttrOrOID *create_OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1PkcsAttribute_(OrgSpongycastleAsn1EstAttrOrOID *self, OrgSpongycastleAsn1PkcsAttribute *attribute);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstAttrOrOID *new_OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1PkcsAttribute_(OrgSpongycastleAsn1PkcsAttribute *attribute) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EstAttrOrOID *create_OrgSpongycastleAsn1EstAttrOrOID_initWithOrgSpongycastleAsn1PkcsAttribute_(OrgSpongycastleAsn1PkcsAttribute *attribute);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstAttrOrOID *OrgSpongycastleAsn1EstAttrOrOID_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EstAttrOrOID)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EstAttrOrOID")
