//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/TBSCertList.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList")
#ifdef RESTRICT_OrgSpongycastleAsn1X509TBSCertList
#define INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509TBSCertList

#if !defined (OrgSpongycastleAsn1X509TBSCertList_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList || defined(INCLUDE_OrgSpongycastleAsn1X509TBSCertList))
#define OrgSpongycastleAsn1X509TBSCertList_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1X500X500Name;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509Time;
@protocol JavaUtilEnumeration;

@interface OrgSpongycastleAsn1X509TBSCertList : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *signature_;
  OrgSpongycastleAsn1X500X500Name *issuer_;
  OrgSpongycastleAsn1X509Time *thisUpdate_;
  OrgSpongycastleAsn1X509Time *nextUpdate_;
  OrgSpongycastleAsn1ASN1Sequence *revokedCertificates_;
  OrgSpongycastleAsn1X509Extensions *crlExtensions_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (OrgSpongycastleAsn1X509Extensions *)getExtensions;

+ (OrgSpongycastleAsn1X509TBSCertList *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                               withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509TBSCertList *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X500X500Name *)getIssuer;

- (OrgSpongycastleAsn1X509Time *)getNextUpdate;

- (id<JavaUtilEnumeration>)getRevokedCertificateEnumeration;

- (IOSObjectArray *)getRevokedCertificates;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getSignature;

- (OrgSpongycastleAsn1X509Time *)getThisUpdate;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

- (jint)getVersionNumber;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509TBSCertList)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, signature_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, issuer_, OrgSpongycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, thisUpdate_, OrgSpongycastleAsn1X509Time *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, nextUpdate_, OrgSpongycastleAsn1X509Time *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, revokedCertificates_, OrgSpongycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList, crlExtensions_, OrgSpongycastleAsn1X509Extensions *)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509TBSCertList *OrgSpongycastleAsn1X509TBSCertList_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509TBSCertList *OrgSpongycastleAsn1X509TBSCertList_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509TBSCertList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509TBSCertList *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509TBSCertList *new_OrgSpongycastleAsn1X509TBSCertList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509TBSCertList *create_OrgSpongycastleAsn1X509TBSCertList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509TBSCertList)

#endif

#if !defined (OrgSpongycastleAsn1X509TBSCertList_CRLEntry_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList || defined(INCLUDE_OrgSpongycastleAsn1X509TBSCertList_CRLEntry))
#define OrgSpongycastleAsn1X509TBSCertList_CRLEntry_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509Time;

@interface OrgSpongycastleAsn1X509TBSCertList_CRLEntry : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Sequence *seq_;
  OrgSpongycastleAsn1X509Extensions *crlEntryExtensions_;
}

#pragma mark Public

- (OrgSpongycastleAsn1X509Extensions *)getExtensions;

+ (OrgSpongycastleAsn1X509TBSCertList_CRLEntry *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1X509Time *)getRevocationDate;

- (OrgSpongycastleAsn1ASN1Integer *)getUserCertificate;

- (jboolean)hasExtensions;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509TBSCertList_CRLEntry)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList_CRLEntry, seq_, OrgSpongycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509TBSCertList_CRLEntry, crlEntryExtensions_, OrgSpongycastleAsn1X509Extensions *)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509TBSCertList_CRLEntry *OrgSpongycastleAsn1X509TBSCertList_CRLEntry_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509TBSCertList_CRLEntry)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509TBSCertList")
