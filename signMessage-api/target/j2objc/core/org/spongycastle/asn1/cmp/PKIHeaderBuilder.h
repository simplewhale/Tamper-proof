//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/PKIHeaderBuilder.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeaderBuilder")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpPKIHeaderBuilder
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeaderBuilder 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeaderBuilder 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpPKIHeaderBuilder

#if !defined (OrgSpongycastleAsn1CmpPKIHeaderBuilder_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeaderBuilder || defined(INCLUDE_OrgSpongycastleAsn1CmpPKIHeaderBuilder))
#define OrgSpongycastleAsn1CmpPKIHeaderBuilder_

@class IOSByteArray;
@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1CmpInfoTypeAndValue;
@class OrgSpongycastleAsn1CmpPKIFreeText;
@class OrgSpongycastleAsn1CmpPKIHeader;
@class OrgSpongycastleAsn1DEROctetString;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@class OrgSpongycastleAsn1X509GeneralName;

@interface OrgSpongycastleAsn1CmpPKIHeaderBuilder : NSObject

#pragma mark Public

- (instancetype)initWithInt:(jint)pvno
withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)sender
withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)recipient;

- (OrgSpongycastleAsn1CmpPKIHeader *)build;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setFreeTextWithOrgSpongycastleAsn1CmpPKIFreeText:(OrgSpongycastleAsn1CmpPKIFreeText *)text;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seqOfInfoTypeAndValue;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithOrgSpongycastleAsn1CmpInfoTypeAndValue:(OrgSpongycastleAsn1CmpInfoTypeAndValue *)genInfo;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithOrgSpongycastleAsn1CmpInfoTypeAndValueArray:(IOSObjectArray *)genInfos;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setMessageTimeWithOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)time;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setProtectionAlgWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)aid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setRecipKIDWithByteArray:(IOSByteArray *)kid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setRecipKIDWithOrgSpongycastleAsn1DEROctetString:(OrgSpongycastleAsn1DEROctetString *)kid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setRecipNonceWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)nonce;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setRecipNonceWithByteArray:(IOSByteArray *)nonce;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setSenderKIDWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)kid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setSenderKIDWithByteArray:(IOSByteArray *)kid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setSenderNonceWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)nonce;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setSenderNonceWithByteArray:(IOSByteArray *)nonce;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setTransactionIDWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)tid;

- (OrgSpongycastleAsn1CmpPKIHeaderBuilder *)setTransactionIDWithByteArray:(IOSByteArray *)tid;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmpPKIHeaderBuilder)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpPKIHeaderBuilder_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1CmpPKIHeaderBuilder *self, jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpPKIHeaderBuilder *new_OrgSpongycastleAsn1CmpPKIHeaderBuilder_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpPKIHeaderBuilder *create_OrgSpongycastleAsn1CmpPKIHeaderBuilder_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpPKIHeaderBuilder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeaderBuilder")
