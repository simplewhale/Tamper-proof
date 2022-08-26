//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/SubjectKeyIdentifier.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectKeyIdentifier")
#ifdef RESTRICT_OrgSpongycastleAsn1X509SubjectKeyIdentifier
#define INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectKeyIdentifier 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectKeyIdentifier 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509SubjectKeyIdentifier

#if !defined (OrgSpongycastleAsn1X509SubjectKeyIdentifier_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectKeyIdentifier || defined(INCLUDE_OrgSpongycastleAsn1X509SubjectKeyIdentifier))
#define OrgSpongycastleAsn1X509SubjectKeyIdentifier_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1X509Extensions;

@interface OrgSpongycastleAsn1X509SubjectKeyIdentifier : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)keyid;

+ (OrgSpongycastleAsn1X509SubjectKeyIdentifier *)fromExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

+ (OrgSpongycastleAsn1X509SubjectKeyIdentifier *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509SubjectKeyIdentifier *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getKeyIdentifier;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Protected

- (instancetype)initWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)keyid;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509SubjectKeyIdentifier)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *OrgSpongycastleAsn1X509SubjectKeyIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *OrgSpongycastleAsn1X509SubjectKeyIdentifier_getInstanceWithId_(id obj);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *OrgSpongycastleAsn1X509SubjectKeyIdentifier_fromExtensionsWithOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1X509Extensions *extensions);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithByteArray_(OrgSpongycastleAsn1X509SubjectKeyIdentifier *self, IOSByteArray *keyid);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *new_OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithByteArray_(IOSByteArray *keyid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *create_OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithByteArray_(IOSByteArray *keyid);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509SubjectKeyIdentifier *self, OrgSpongycastleAsn1ASN1OctetString *keyid);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *new_OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *keyid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509SubjectKeyIdentifier *create_OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *keyid);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509SubjectKeyIdentifier)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509SubjectKeyIdentifier")
