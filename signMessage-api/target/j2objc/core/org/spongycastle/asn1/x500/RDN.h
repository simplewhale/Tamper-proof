//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x500/RDN.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500RDN")
#ifdef RESTRICT_OrgSpongycastleAsn1X500RDN
#define INCLUDE_ALL_OrgSpongycastleAsn1X500RDN 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X500RDN 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X500RDN

#if !defined (OrgSpongycastleAsn1X500RDN_) && (INCLUDE_ALL_OrgSpongycastleAsn1X500RDN || defined(INCLUDE_OrgSpongycastleAsn1X500RDN))
#define OrgSpongycastleAsn1X500RDN_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X500AttributeTypeAndValue;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1X500RDN : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)value;

- (instancetype)initWithOrgSpongycastleAsn1X500AttributeTypeAndValue:(OrgSpongycastleAsn1X500AttributeTypeAndValue *)attrTAndV;

- (instancetype)initWithOrgSpongycastleAsn1X500AttributeTypeAndValueArray:(IOSObjectArray *)aAndVs;

- (OrgSpongycastleAsn1X500AttributeTypeAndValue *)getFirst;

+ (OrgSpongycastleAsn1X500RDN *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getTypesAndValues;

- (jboolean)isMultiValued;

- (jint)size;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X500RDN)

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *OrgSpongycastleAsn1X500RDN_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1X500RDN *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> value);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *new_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *create_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> value);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValue_(OrgSpongycastleAsn1X500RDN *self, OrgSpongycastleAsn1X500AttributeTypeAndValue *attrTAndV);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *new_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValue_(OrgSpongycastleAsn1X500AttributeTypeAndValue *attrTAndV) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *create_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValue_(OrgSpongycastleAsn1X500AttributeTypeAndValue *attrTAndV);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValueArray_(OrgSpongycastleAsn1X500RDN *self, IOSObjectArray *aAndVs);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *new_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValueArray_(IOSObjectArray *aAndVs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500RDN *create_OrgSpongycastleAsn1X500RDN_initWithOrgSpongycastleAsn1X500AttributeTypeAndValueArray_(IOSObjectArray *aAndVs);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X500RDN)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500RDN")
