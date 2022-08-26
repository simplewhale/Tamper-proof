//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/ProtectedPart.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpProtectedPart")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpProtectedPart
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpProtectedPart 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpProtectedPart 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpProtectedPart

#if !defined (OrgSpongycastleAsn1CmpProtectedPart_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpProtectedPart || defined(INCLUDE_OrgSpongycastleAsn1CmpProtectedPart))
#define OrgSpongycastleAsn1CmpProtectedPart_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CmpPKIBody;
@class OrgSpongycastleAsn1CmpPKIHeader;

@interface OrgSpongycastleAsn1CmpProtectedPart : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmpPKIHeader:(OrgSpongycastleAsn1CmpPKIHeader *)header
                      withOrgSpongycastleAsn1CmpPKIBody:(OrgSpongycastleAsn1CmpPKIBody *)body;

- (OrgSpongycastleAsn1CmpPKIBody *)getBody;

- (OrgSpongycastleAsn1CmpPKIHeader *)getHeader;

+ (OrgSpongycastleAsn1CmpProtectedPart *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmpProtectedPart)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpProtectedPart *OrgSpongycastleAsn1CmpProtectedPart_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpProtectedPart_initWithOrgSpongycastleAsn1CmpPKIHeader_withOrgSpongycastleAsn1CmpPKIBody_(OrgSpongycastleAsn1CmpProtectedPart *self, OrgSpongycastleAsn1CmpPKIHeader *header, OrgSpongycastleAsn1CmpPKIBody *body);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpProtectedPart *new_OrgSpongycastleAsn1CmpProtectedPart_initWithOrgSpongycastleAsn1CmpPKIHeader_withOrgSpongycastleAsn1CmpPKIBody_(OrgSpongycastleAsn1CmpPKIHeader *header, OrgSpongycastleAsn1CmpPKIBody *body) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpProtectedPart *create_OrgSpongycastleAsn1CmpProtectedPart_initWithOrgSpongycastleAsn1CmpPKIHeader_withOrgSpongycastleAsn1CmpPKIBody_(OrgSpongycastleAsn1CmpPKIHeader *header, OrgSpongycastleAsn1CmpPKIBody *body);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpProtectedPart)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpProtectedPart")
