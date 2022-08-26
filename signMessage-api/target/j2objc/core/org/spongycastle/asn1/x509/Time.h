//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/Time.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509Time")
#ifdef RESTRICT_OrgSpongycastleAsn1X509Time
#define INCLUDE_ALL_OrgSpongycastleAsn1X509Time 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509Time 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509Time

#if !defined (OrgSpongycastleAsn1X509Time_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509Time || defined(INCLUDE_OrgSpongycastleAsn1X509Time))
#define OrgSpongycastleAsn1X509Time_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1Choice 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Choice 1
#include "org/spongycastle/asn1/ASN1Choice.h"

@class JavaUtilDate;
@class JavaUtilLocale;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;

@interface OrgSpongycastleAsn1X509Time : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleAsn1ASN1Choice > {
 @public
  OrgSpongycastleAsn1ASN1Primitive *time_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)time;

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time;

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time
                  withJavaUtilLocale:(JavaUtilLocale *)locale;

- (JavaUtilDate *)getDate;

+ (OrgSpongycastleAsn1X509Time *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                        withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509Time *)getInstanceWithId:(id)obj;

- (NSString *)getTime;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509Time)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509Time, time_, OrgSpongycastleAsn1ASN1Primitive *)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *OrgSpongycastleAsn1X509Time_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509Time_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1X509Time *self, OrgSpongycastleAsn1ASN1Primitive *time);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *new_OrgSpongycastleAsn1X509Time_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *create_OrgSpongycastleAsn1X509Time_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *time);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_(OrgSpongycastleAsn1X509Time *self, JavaUtilDate *time);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *new_OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_(JavaUtilDate *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *create_OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_(JavaUtilDate *time);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_withJavaUtilLocale_(OrgSpongycastleAsn1X509Time *self, JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *new_OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *create_OrgSpongycastleAsn1X509Time_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Time *OrgSpongycastleAsn1X509Time_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509Time)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509Time")