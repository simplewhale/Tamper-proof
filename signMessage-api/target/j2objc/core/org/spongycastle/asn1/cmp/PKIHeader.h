//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/PKIHeader.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeader")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpPKIHeader
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeader 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeader 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpPKIHeader

#if !defined (OrgSpongycastleAsn1CmpPKIHeader_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeader || defined(INCLUDE_OrgSpongycastleAsn1CmpPKIHeader))
#define OrgSpongycastleAsn1CmpPKIHeader_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CmpPKIFreeText;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@class OrgSpongycastleAsn1X509GeneralName;

@interface OrgSpongycastleAsn1CmpPKIHeader : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithInt:(jint)pvno
withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)sender
withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)recipient;

- (OrgSpongycastleAsn1CmpPKIFreeText *)getFreeText;

- (IOSObjectArray *)getGeneralInfo;

+ (OrgSpongycastleAsn1CmpPKIHeader *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getMessageTime;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getProtectionAlg;

- (OrgSpongycastleAsn1ASN1Integer *)getPvno;

- (OrgSpongycastleAsn1X509GeneralName *)getRecipient;

- (OrgSpongycastleAsn1ASN1OctetString *)getRecipKID;

- (OrgSpongycastleAsn1ASN1OctetString *)getRecipNonce;

- (OrgSpongycastleAsn1X509GeneralName *)getSender;

- (OrgSpongycastleAsn1ASN1OctetString *)getSenderKID;

- (OrgSpongycastleAsn1ASN1OctetString *)getSenderNonce;

- (OrgSpongycastleAsn1ASN1OctetString *)getTransactionID;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1CmpPKIHeader)

inline OrgSpongycastleAsn1X509GeneralName *OrgSpongycastleAsn1CmpPKIHeader_get_NULL_NAME(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1X509GeneralName *OrgSpongycastleAsn1CmpPKIHeader_NULL_NAME;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmpPKIHeader, NULL_NAME, OrgSpongycastleAsn1X509GeneralName *)

inline jint OrgSpongycastleAsn1CmpPKIHeader_get_CMP_1999(void);
#define OrgSpongycastleAsn1CmpPKIHeader_CMP_1999 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1CmpPKIHeader, CMP_1999, jint)

inline jint OrgSpongycastleAsn1CmpPKIHeader_get_CMP_2000(void);
#define OrgSpongycastleAsn1CmpPKIHeader_CMP_2000 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1CmpPKIHeader, CMP_2000, jint)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpPKIHeader *OrgSpongycastleAsn1CmpPKIHeader_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpPKIHeader_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1CmpPKIHeader *self, jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpPKIHeader *new_OrgSpongycastleAsn1CmpPKIHeader_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpPKIHeader *create_OrgSpongycastleAsn1CmpPKIHeader_initWithInt_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1X509GeneralName_(jint pvno, OrgSpongycastleAsn1X509GeneralName *sender, OrgSpongycastleAsn1X509GeneralName *recipient);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpPKIHeader)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpPKIHeader")