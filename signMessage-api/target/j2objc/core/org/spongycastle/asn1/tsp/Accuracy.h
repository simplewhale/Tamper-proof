//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/tsp/Accuracy.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1TspAccuracy")
#ifdef RESTRICT_OrgSpongycastleAsn1TspAccuracy
#define INCLUDE_ALL_OrgSpongycastleAsn1TspAccuracy 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1TspAccuracy 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1TspAccuracy

#if !defined (OrgSpongycastleAsn1TspAccuracy_) && (INCLUDE_ALL_OrgSpongycastleAsn1TspAccuracy || defined(INCLUDE_OrgSpongycastleAsn1TspAccuracy))
#define OrgSpongycastleAsn1TspAccuracy_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1TspAccuracy : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Integer *seconds_;
  OrgSpongycastleAsn1ASN1Integer *millis_;
  OrgSpongycastleAsn1ASN1Integer *micros_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)seconds
                    withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)millis
                    withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)micros;

+ (OrgSpongycastleAsn1TspAccuracy *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Integer *)getMicros;

- (OrgSpongycastleAsn1ASN1Integer *)getMillis;

- (OrgSpongycastleAsn1ASN1Integer *)getSeconds;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Protected

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1TspAccuracy)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1TspAccuracy, seconds_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1TspAccuracy, millis_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1TspAccuracy, micros_, OrgSpongycastleAsn1ASN1Integer *)

inline jint OrgSpongycastleAsn1TspAccuracy_get_MIN_MILLIS(void);
#define OrgSpongycastleAsn1TspAccuracy_MIN_MILLIS 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1TspAccuracy, MIN_MILLIS, jint)

inline jint OrgSpongycastleAsn1TspAccuracy_get_MAX_MILLIS(void);
#define OrgSpongycastleAsn1TspAccuracy_MAX_MILLIS 999
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1TspAccuracy, MAX_MILLIS, jint)

inline jint OrgSpongycastleAsn1TspAccuracy_get_MIN_MICROS(void);
#define OrgSpongycastleAsn1TspAccuracy_MIN_MICROS 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1TspAccuracy, MIN_MICROS, jint)

inline jint OrgSpongycastleAsn1TspAccuracy_get_MAX_MICROS(void);
#define OrgSpongycastleAsn1TspAccuracy_MAX_MICROS 999
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1TspAccuracy, MAX_MICROS, jint)

FOUNDATION_EXPORT void OrgSpongycastleAsn1TspAccuracy_init(OrgSpongycastleAsn1TspAccuracy *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1TspAccuracy *new_OrgSpongycastleAsn1TspAccuracy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1TspAccuracy *create_OrgSpongycastleAsn1TspAccuracy_init(void);

FOUNDATION_EXPORT void OrgSpongycastleAsn1TspAccuracy_initWithOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_(OrgSpongycastleAsn1TspAccuracy *self, OrgSpongycastleAsn1ASN1Integer *seconds, OrgSpongycastleAsn1ASN1Integer *millis, OrgSpongycastleAsn1ASN1Integer *micros);

FOUNDATION_EXPORT OrgSpongycastleAsn1TspAccuracy *new_OrgSpongycastleAsn1TspAccuracy_initWithOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_(OrgSpongycastleAsn1ASN1Integer *seconds, OrgSpongycastleAsn1ASN1Integer *millis, OrgSpongycastleAsn1ASN1Integer *micros) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1TspAccuracy *create_OrgSpongycastleAsn1TspAccuracy_initWithOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Integer_(OrgSpongycastleAsn1ASN1Integer *seconds, OrgSpongycastleAsn1ASN1Integer *millis, OrgSpongycastleAsn1ASN1Integer *micros);

FOUNDATION_EXPORT OrgSpongycastleAsn1TspAccuracy *OrgSpongycastleAsn1TspAccuracy_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1TspAccuracy)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1TspAccuracy")
