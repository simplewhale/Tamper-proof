//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/AttributeTable.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAttributeTable")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsAttributeTable
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAttributeTable 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAttributeTable 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsAttributeTable

#if !defined (OrgSpongycastleAsn1CmsAttributeTable_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsAttributeTable || defined(INCLUDE_OrgSpongycastleAsn1CmsAttributeTable))
#define OrgSpongycastleAsn1CmsAttributeTable_

@class JavaUtilHashtable;
@class OrgSpongycastleAsn1ASN1EncodableVector;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Set;
@class OrgSpongycastleAsn1CmsAttribute;
@class OrgSpongycastleAsn1CmsAttributes;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1CmsAttributeTable : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v;

- (instancetype)initWithOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)s;

- (instancetype)initWithOrgSpongycastleAsn1CmsAttribute:(OrgSpongycastleAsn1CmsAttribute *)attr;

- (instancetype)initWithOrgSpongycastleAsn1CmsAttributes:(OrgSpongycastleAsn1CmsAttributes *)attrs;

- (instancetype)initWithJavaUtilHashtable:(JavaUtilHashtable *)attrs;

- (OrgSpongycastleAsn1CmsAttributeTable *)addWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)attrType
                                                    withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)attrValue;

- (OrgSpongycastleAsn1CmsAttribute *)getWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (OrgSpongycastleAsn1ASN1EncodableVector *)getAllWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (OrgSpongycastleAsn1CmsAttributeTable *)removeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)attrType;

- (jint)size;

- (OrgSpongycastleAsn1ASN1EncodableVector *)toASN1EncodableVector;

- (OrgSpongycastleAsn1CmsAttributes *)toASN1Structure;

- (JavaUtilHashtable *)toHashtable;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsAttributeTable)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAttributeTable_initWithJavaUtilHashtable_(OrgSpongycastleAsn1CmsAttributeTable *self, JavaUtilHashtable *attrs);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *new_OrgSpongycastleAsn1CmsAttributeTable_initWithJavaUtilHashtable_(JavaUtilHashtable *attrs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *create_OrgSpongycastleAsn1CmsAttributeTable_initWithJavaUtilHashtable_(JavaUtilHashtable *attrs);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1CmsAttributeTable *self, OrgSpongycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *new_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *create_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsAttributeTable *self, OrgSpongycastleAsn1ASN1Set *s);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *new_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1Set *s) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *create_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1Set *s);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttribute_(OrgSpongycastleAsn1CmsAttributeTable *self, OrgSpongycastleAsn1CmsAttribute *attr);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *new_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttribute_(OrgSpongycastleAsn1CmsAttribute *attr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *create_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttribute_(OrgSpongycastleAsn1CmsAttribute *attr);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttributes_(OrgSpongycastleAsn1CmsAttributeTable *self, OrgSpongycastleAsn1CmsAttributes *attrs);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *new_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttributes_(OrgSpongycastleAsn1CmsAttributes *attrs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAttributeTable *create_OrgSpongycastleAsn1CmsAttributeTable_initWithOrgSpongycastleAsn1CmsAttributes_(OrgSpongycastleAsn1CmsAttributes *attrs);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsAttributeTable)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAttributeTable")
