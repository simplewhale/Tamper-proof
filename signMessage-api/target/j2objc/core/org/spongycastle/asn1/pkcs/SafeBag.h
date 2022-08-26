//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/SafeBag.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsSafeBag")
#ifdef RESTRICT_OrgSpongycastleAsn1PkcsSafeBag
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsSafeBag 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsSafeBag 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1PkcsSafeBag

#if !defined (OrgSpongycastleAsn1PkcsSafeBag_) && (INCLUDE_ALL_OrgSpongycastleAsn1PkcsSafeBag || defined(INCLUDE_OrgSpongycastleAsn1PkcsSafeBag))
#define OrgSpongycastleAsn1PkcsSafeBag_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Set;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1PkcsSafeBag : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj;

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj
                                 withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)bagAttributes;

- (OrgSpongycastleAsn1ASN1Set *)getBagAttributes;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getBagId;

- (id<OrgSpongycastleAsn1ASN1Encodable>)getBagValue;

+ (OrgSpongycastleAsn1PkcsSafeBag *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1PkcsSafeBag)

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsSafeBag *OrgSpongycastleAsn1PkcsSafeBag_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1PkcsSafeBag)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsSafeBag")
