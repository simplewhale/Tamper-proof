//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/eac/PublicKeyDataObject.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacPublicKeyDataObject")
#ifdef RESTRICT_OrgSpongycastleAsn1EacPublicKeyDataObject
#define INCLUDE_ALL_OrgSpongycastleAsn1EacPublicKeyDataObject 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EacPublicKeyDataObject 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EacPublicKeyDataObject

#if !defined (OrgSpongycastleAsn1EacPublicKeyDataObject_) && (INCLUDE_ALL_OrgSpongycastleAsn1EacPublicKeyDataObject || defined(INCLUDE_OrgSpongycastleAsn1EacPublicKeyDataObject))
#define OrgSpongycastleAsn1EacPublicKeyDataObject_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;

@interface OrgSpongycastleAsn1EacPublicKeyDataObject : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)init;

+ (OrgSpongycastleAsn1EacPublicKeyDataObject *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getUsage;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EacPublicKeyDataObject)

FOUNDATION_EXPORT void OrgSpongycastleAsn1EacPublicKeyDataObject_init(OrgSpongycastleAsn1EacPublicKeyDataObject *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1EacPublicKeyDataObject *OrgSpongycastleAsn1EacPublicKeyDataObject_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EacPublicKeyDataObject)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacPublicKeyDataObject")
