//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/est/CsrAttrs.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EstCsrAttrs")
#ifdef RESTRICT_OrgSpongycastleAsn1EstCsrAttrs
#define INCLUDE_ALL_OrgSpongycastleAsn1EstCsrAttrs 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EstCsrAttrs 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EstCsrAttrs

#if !defined (OrgSpongycastleAsn1EstCsrAttrs_) && (INCLUDE_ALL_OrgSpongycastleAsn1EstCsrAttrs || defined(INCLUDE_OrgSpongycastleAsn1EstCsrAttrs))
#define OrgSpongycastleAsn1EstCsrAttrs_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1EstAttrOrOID;

@interface OrgSpongycastleAsn1EstCsrAttrs : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1EstAttrOrOID:(OrgSpongycastleAsn1EstAttrOrOID *)attrOrOID;

- (instancetype)initWithOrgSpongycastleAsn1EstAttrOrOIDArray:(IOSObjectArray *)attrOrOIDs;

- (IOSObjectArray *)getAttrOrOIDs;

+ (OrgSpongycastleAsn1EstCsrAttrs *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                           withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1EstCsrAttrs *)getInstanceWithId:(id)obj;

- (jint)size;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EstCsrAttrs)

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *OrgSpongycastleAsn1EstCsrAttrs_getInstanceWithId_(id obj);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *OrgSpongycastleAsn1EstCsrAttrs_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOID_(OrgSpongycastleAsn1EstCsrAttrs *self, OrgSpongycastleAsn1EstAttrOrOID *attrOrOID);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *new_OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOID_(OrgSpongycastleAsn1EstAttrOrOID *attrOrOID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *create_OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOID_(OrgSpongycastleAsn1EstAttrOrOID *attrOrOID);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOIDArray_(OrgSpongycastleAsn1EstCsrAttrs *self, IOSObjectArray *attrOrOIDs);

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *new_OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOIDArray_(IOSObjectArray *attrOrOIDs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EstCsrAttrs *create_OrgSpongycastleAsn1EstCsrAttrs_initWithOrgSpongycastleAsn1EstAttrOrOIDArray_(IOSObjectArray *attrOrOIDs);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EstCsrAttrs)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EstCsrAttrs")
