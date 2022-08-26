//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/Target.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509Target")
#ifdef RESTRICT_OrgSpongycastleAsn1X509Target
#define INCLUDE_ALL_OrgSpongycastleAsn1X509Target 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509Target 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509Target

#if !defined (OrgSpongycastleAsn1X509Target_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509Target || defined(INCLUDE_OrgSpongycastleAsn1X509Target))
#define OrgSpongycastleAsn1X509Target_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1Choice 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Choice 1
#include "org/spongycastle/asn1/ASN1Choice.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509GeneralName;

@interface OrgSpongycastleAsn1X509Target : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype)initWithInt:(jint)type
withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)name;

+ (OrgSpongycastleAsn1X509Target *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X509GeneralName *)getTargetGroup;

- (OrgSpongycastleAsn1X509GeneralName *)getTargetName;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509Target)

inline jint OrgSpongycastleAsn1X509Target_get_targetName(void);
#define OrgSpongycastleAsn1X509Target_targetName 0
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1X509Target, targetName, jint)

inline jint OrgSpongycastleAsn1X509Target_get_targetGroup(void);
#define OrgSpongycastleAsn1X509Target_targetGroup 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1X509Target, targetGroup, jint)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Target *OrgSpongycastleAsn1X509Target_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509Target_initWithInt_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1X509Target *self, jint type, OrgSpongycastleAsn1X509GeneralName *name);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Target *new_OrgSpongycastleAsn1X509Target_initWithInt_withOrgSpongycastleAsn1X509GeneralName_(jint type, OrgSpongycastleAsn1X509GeneralName *name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509Target *create_OrgSpongycastleAsn1X509Target_initWithInt_withOrgSpongycastleAsn1X509GeneralName_(jint type, OrgSpongycastleAsn1X509GeneralName *name);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509Target)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509Target")
