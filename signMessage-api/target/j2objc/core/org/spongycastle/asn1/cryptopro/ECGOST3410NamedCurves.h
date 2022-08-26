//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cryptopro/ECGOST3410NamedCurves.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves")
#ifdef RESTRICT_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves
#define INCLUDE_ALL_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves

#if !defined (OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_) && (INCLUDE_ALL_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves || defined(INCLUDE_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves))
#define OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_

@class JavaUtilHashtable;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleCryptoParamsECDomainParameters;
@protocol JavaUtilEnumeration;

@interface OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves : NSObject

#pragma mark Public

- (instancetype)init;

+ (OrgSpongycastleCryptoParamsECDomainParameters *)getByNameWithNSString:(NSString *)name;

+ (OrgSpongycastleCryptoParamsECDomainParameters *)getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

+ (NSString *)getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

+ (id<JavaUtilEnumeration>)getNames;

+ (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves)

inline JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_get_objIds(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_objIds;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves, objIds, JavaUtilHashtable *)

inline JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_get_params(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_params;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves, params, JavaUtilHashtable *)

inline JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_get_names(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilHashtable *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_names;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves, names, JavaUtilHashtable *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_init(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves *new_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves *create_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_init(void);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsECDomainParameters *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT id<JavaUtilEnumeration> OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_getNames(void);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsECDomainParameters *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_getByNameWithNSString_(NSString *name);

FOUNDATION_EXPORT NSString *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves_getOIDWithNSString_(NSString *name);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CryptoproECGOST3410NamedCurves")
