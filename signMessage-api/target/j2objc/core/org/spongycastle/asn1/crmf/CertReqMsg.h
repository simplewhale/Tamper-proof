//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/CertReqMsg.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CrmfCertReqMsg")
#ifdef RESTRICT_OrgSpongycastleAsn1CrmfCertReqMsg
#define INCLUDE_ALL_OrgSpongycastleAsn1CrmfCertReqMsg 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CrmfCertReqMsg 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CrmfCertReqMsg

#if !defined (OrgSpongycastleAsn1CrmfCertReqMsg_) && (INCLUDE_ALL_OrgSpongycastleAsn1CrmfCertReqMsg || defined(INCLUDE_OrgSpongycastleAsn1CrmfCertReqMsg))
#define OrgSpongycastleAsn1CrmfCertReqMsg_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1CrmfCertRequest;
@class OrgSpongycastleAsn1CrmfProofOfPossession;

@interface OrgSpongycastleAsn1CrmfCertReqMsg : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CrmfCertRequest:(OrgSpongycastleAsn1CrmfCertRequest *)certReq
              withOrgSpongycastleAsn1CrmfProofOfPossession:(OrgSpongycastleAsn1CrmfProofOfPossession *)pop
     withOrgSpongycastleAsn1CrmfAttributeTypeAndValueArray:(IOSObjectArray *)regInfo;

- (OrgSpongycastleAsn1CrmfCertRequest *)getCertReq;

+ (OrgSpongycastleAsn1CrmfCertReqMsg *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                              withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1CrmfCertReqMsg *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1CrmfProofOfPossession *)getPop;

- (OrgSpongycastleAsn1CrmfProofOfPossession *)getPopo;

- (IOSObjectArray *)getRegInfo;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CrmfCertReqMsg)

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfCertReqMsg *OrgSpongycastleAsn1CrmfCertReqMsg_getInstanceWithId_(id o);

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfCertReqMsg *OrgSpongycastleAsn1CrmfCertReqMsg_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CrmfCertReqMsg_initWithOrgSpongycastleAsn1CrmfCertRequest_withOrgSpongycastleAsn1CrmfProofOfPossession_withOrgSpongycastleAsn1CrmfAttributeTypeAndValueArray_(OrgSpongycastleAsn1CrmfCertReqMsg *self, OrgSpongycastleAsn1CrmfCertRequest *certReq, OrgSpongycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfCertReqMsg *new_OrgSpongycastleAsn1CrmfCertReqMsg_initWithOrgSpongycastleAsn1CrmfCertRequest_withOrgSpongycastleAsn1CrmfProofOfPossession_withOrgSpongycastleAsn1CrmfAttributeTypeAndValueArray_(OrgSpongycastleAsn1CrmfCertRequest *certReq, OrgSpongycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfCertReqMsg *create_OrgSpongycastleAsn1CrmfCertReqMsg_initWithOrgSpongycastleAsn1CrmfCertRequest_withOrgSpongycastleAsn1CrmfProofOfPossession_withOrgSpongycastleAsn1CrmfAttributeTypeAndValueArray_(OrgSpongycastleAsn1CrmfCertRequest *certReq, OrgSpongycastleAsn1CrmfProofOfPossession *pop, IOSObjectArray *regInfo);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CrmfCertReqMsg)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CrmfCertReqMsg")
