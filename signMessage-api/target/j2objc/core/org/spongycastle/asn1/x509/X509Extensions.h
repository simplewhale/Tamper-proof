//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/X509Extensions.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509X509Extensions")
#ifdef RESTRICT_OrgSpongycastleAsn1X509X509Extensions
#define INCLUDE_ALL_OrgSpongycastleAsn1X509X509Extensions 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509X509Extensions 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509X509Extensions

#if !defined (OrgSpongycastleAsn1X509X509Extensions_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509X509Extensions || defined(INCLUDE_OrgSpongycastleAsn1X509X509Extensions))
#define OrgSpongycastleAsn1X509X509Extensions_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1X509X509Extension;
@protocol JavaUtilEnumeration;

@interface OrgSpongycastleAsn1X509X509Extensions : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (instancetype)initWithJavaUtilHashtable:(JavaUtilHashtable *)extensions;

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)ordering
                 withJavaUtilHashtable:(JavaUtilHashtable *)extensions;

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)objectIDs
                    withJavaUtilVector:(JavaUtilVector *)values;

- (jboolean)equivalentWithOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)other;

- (IOSObjectArray *)getCriticalExtensionOIDs;

- (OrgSpongycastleAsn1X509X509Extension *)getExtensionWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (IOSObjectArray *)getExtensionOIDs;

+ (OrgSpongycastleAsn1X509X509Extensions *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509X509Extensions *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getNonCriticalExtensionOIDs;

- (id<JavaUtilEnumeration>)oids;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1X509X509Extensions)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_SubjectDirectoryAttributes(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_SubjectDirectoryAttributes;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, SubjectDirectoryAttributes, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_SubjectKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_SubjectKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, SubjectKeyIdentifier, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_KeyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_KeyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, KeyUsage, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_PrivateKeyUsagePeriod(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, PrivateKeyUsagePeriod, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_SubjectAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_SubjectAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, SubjectAlternativeName, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_IssuerAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_IssuerAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, IssuerAlternativeName, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_BasicConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_BasicConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, BasicConstraints, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_CRLNumber(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_CRLNumber;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, CRLNumber, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_ReasonCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_ReasonCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, ReasonCode, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_InstructionCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_InstructionCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, InstructionCode, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_InvalidityDate(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_InvalidityDate;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, InvalidityDate, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_DeltaCRLIndicator(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_DeltaCRLIndicator;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, DeltaCRLIndicator, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_IssuingDistributionPoint(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_IssuingDistributionPoint;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, IssuingDistributionPoint, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_CertificateIssuer(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_CertificateIssuer;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, CertificateIssuer, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_NameConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_NameConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, NameConstraints, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_CRLDistributionPoints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_CRLDistributionPoints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, CRLDistributionPoints, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_CertificatePolicies(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_CertificatePolicies;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, CertificatePolicies, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_PolicyMappings(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_PolicyMappings;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, PolicyMappings, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_AuthorityKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_AuthorityKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, AuthorityKeyIdentifier, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_PolicyConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_PolicyConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, PolicyConstraints, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_ExtendedKeyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_ExtendedKeyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, ExtendedKeyUsage, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_FreshestCRL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_FreshestCRL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, FreshestCRL, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_InhibitAnyPolicy(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_InhibitAnyPolicy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, InhibitAnyPolicy, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_AuthorityInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_AuthorityInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, AuthorityInfoAccess, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_SubjectInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_SubjectInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, SubjectInfoAccess, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_LogoType(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_LogoType;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, LogoType, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_BiometricInfo(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_BiometricInfo;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, BiometricInfo, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_QCStatements(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_QCStatements;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, QCStatements, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_AuditIdentity(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_AuditIdentity;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, AuditIdentity, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_NoRevAvail(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_NoRevAvail;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, NoRevAvail, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_get_TargetInformation(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extensions_TargetInformation;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1X509X509Extensions, TargetInformation, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *OrgSpongycastleAsn1X509X509Extensions_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *OrgSpongycastleAsn1X509X509Extensions_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509X509Extensions_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509X509Extensions *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *new_OrgSpongycastleAsn1X509X509Extensions_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *create_OrgSpongycastleAsn1X509X509Extensions_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(OrgSpongycastleAsn1X509X509Extensions *self, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *new_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *create_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(OrgSpongycastleAsn1X509X509Extensions *self, JavaUtilVector *ordering, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *new_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *create_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(OrgSpongycastleAsn1X509X509Extensions *self, JavaUtilVector *objectIDs, JavaUtilVector *values);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *new_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509Extensions *create_OrgSpongycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509X509Extensions)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509X509Extensions")
