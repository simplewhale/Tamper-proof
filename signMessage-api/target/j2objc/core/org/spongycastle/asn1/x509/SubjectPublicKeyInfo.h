//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/SubjectPublicKeyInfo.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectPublicKeyInfo")
#ifdef RESTRICT_OrgSpongycastleAsn1X509SubjectPublicKeyInfo
#define INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectPublicKeyInfo 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectPublicKeyInfo 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509SubjectPublicKeyInfo

#if !defined (OrgSpongycastleAsn1X509SubjectPublicKeyInfo_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectPublicKeyInfo || defined(INCLUDE_OrgSpongycastleAsn1X509SubjectPublicKeyInfo))
#define OrgSpongycastleAsn1X509SubjectPublicKeyInfo_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1DERBitString;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1X509SubjectPublicKeyInfo : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)algId
                              withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)publicKey;

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)algId
                                                     withByteArray:(IOSByteArray *)publicKey;

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getAlgorithm;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getAlgorithmId;

+ (OrgSpongycastleAsn1X509SubjectPublicKeyInfo *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509SubjectPublicKeyInfo *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)getPublicKey;

- (OrgSpongycastleAsn1DERBitString *)getPublicKeyData;

- (OrgSpongycastleAsn1ASN1Primitive *)parsePublicKey;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509SubjectPublicKeyInfo)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *OrgSpongycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *OrgSpongycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1X509SubjectPublicKeyInfo *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, id<OrgSpongycastleAsn1ASN1Encodable> publicKey);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *new_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, id<OrgSpongycastleAsn1ASN1Encodable> publicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *create_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, id<OrgSpongycastleAsn1ASN1Encodable> publicKey);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509SubjectPublicKeyInfo *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *publicKey);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *new_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *publicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *create_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *publicKey);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509SubjectPublicKeyInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *new_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectPublicKeyInfo *create_OrgSpongycastleAsn1X509SubjectPublicKeyInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509SubjectPublicKeyInfo)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectPublicKeyInfo")
