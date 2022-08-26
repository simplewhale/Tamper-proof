//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/PKIResponse.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIResponse")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcPKIResponse
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIResponse 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIResponse 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcPKIResponse

#if !defined (OrgSpongycastleAsn1CmcPKIResponse_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIResponse || defined(INCLUDE_OrgSpongycastleAsn1CmcPKIResponse))
#define OrgSpongycastleAsn1CmcPKIResponse_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1TaggedObject;

@interface OrgSpongycastleAsn1CmcPKIResponse : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (OrgSpongycastleAsn1ASN1Sequence *)getCmsSequence;

- (OrgSpongycastleAsn1ASN1Sequence *)getControlSequence;

+ (OrgSpongycastleAsn1CmcPKIResponse *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                              withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1CmcPKIResponse *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Sequence *)getOtherMsgSequence;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmcPKIResponse)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcPKIResponse *OrgSpongycastleAsn1CmcPKIResponse_getInstanceWithId_(id o);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcPKIResponse *OrgSpongycastleAsn1CmcPKIResponse_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcPKIResponse)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIResponse")
