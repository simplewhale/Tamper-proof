//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/nist/NISTNamedCurves.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1NistNISTNamedCurves")
#ifdef RESTRICT_OrgSpongycastleAsn1NistNISTNamedCurves
#define INCLUDE_ALL_OrgSpongycastleAsn1NistNISTNamedCurves 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1NistNISTNamedCurves 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1NistNISTNamedCurves

#if !defined (OrgSpongycastleAsn1NistNISTNamedCurves_) && (INCLUDE_ALL_OrgSpongycastleAsn1NistNISTNamedCurves || defined(INCLUDE_OrgSpongycastleAsn1NistNISTNamedCurves))
#define OrgSpongycastleAsn1NistNISTNamedCurves_

@class JavaUtilHashtable;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1X9X9ECParameters;
@protocol JavaUtilEnumeration;

@interface OrgSpongycastleAsn1NistNISTNamedCurves : NSObject

#pragma mark Public

- (instancetype)init;

+ (OrgSpongycastleAsn1X9X9ECParameters *)getByNameWithNSString:(NSString *)name;

+ (OrgSpongycastleAsn1X9X9ECParameters *)getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

+ (NSString *)getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

+ (id<JavaUtilEnumeration>)getNames;

+ (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name;

#pragma mark Package-Private

+ (void)defineCurveWithNSString:(NSString *)name
withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1NistNISTNamedCurves)

inline JavaUtilHashtable *OrgSpongycastleAsn1NistNISTNamedCurves_get_objIds(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleAsn1NistNISTNamedCurves_objIds;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1NistNISTNamedCurves, objIds, JavaUtilHashtable *)

inline JavaUtilHashtable *OrgSpongycastleAsn1NistNISTNamedCurves_get_names(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleAsn1NistNISTNamedCurves_names;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1NistNISTNamedCurves, names, JavaUtilHashtable *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1NistNISTNamedCurves_init(OrgSpongycastleAsn1NistNISTNamedCurves *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1NistNISTNamedCurves *new_OrgSpongycastleAsn1NistNISTNamedCurves_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1NistNISTNamedCurves *create_OrgSpongycastleAsn1NistNISTNamedCurves_init(void);

FOUNDATION_EXPORT void OrgSpongycastleAsn1NistNISTNamedCurves_defineCurveWithNSString_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(NSString *name, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT OrgSpongycastleAsn1X9X9ECParameters *OrgSpongycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(NSString *name);

FOUNDATION_EXPORT OrgSpongycastleAsn1X9X9ECParameters *OrgSpongycastleAsn1NistNISTNamedCurves_getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1NistNISTNamedCurves_getOIDWithNSString_(NSString *name);

FOUNDATION_EXPORT NSString *OrgSpongycastleAsn1NistNISTNamedCurves_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT id<JavaUtilEnumeration> OrgSpongycastleAsn1NistNISTNamedCurves_getNames(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1NistNISTNamedCurves)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1NistNISTNamedCurves")
