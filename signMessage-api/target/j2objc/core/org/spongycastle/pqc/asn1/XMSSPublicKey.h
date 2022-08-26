//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/asn1/XMSSPublicKey.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSPublicKey")
#ifdef RESTRICT_OrgSpongycastlePqcAsn1XMSSPublicKey
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSPublicKey 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSPublicKey 1
#endif
#undef RESTRICT_OrgSpongycastlePqcAsn1XMSSPublicKey

#if !defined (OrgSpongycastlePqcAsn1XMSSPublicKey_) && (INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSPublicKey || defined(INCLUDE_OrgSpongycastlePqcAsn1XMSSPublicKey))
#define OrgSpongycastlePqcAsn1XMSSPublicKey_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastlePqcAsn1XMSSPublicKey : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)publicSeed
                    withByteArray:(IOSByteArray *)root;

+ (OrgSpongycastlePqcAsn1XMSSPublicKey *)getInstanceWithId:(id)o;

- (IOSByteArray *)getPublicSeed;

- (IOSByteArray *)getRoot;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcAsn1XMSSPublicKey)

FOUNDATION_EXPORT void OrgSpongycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(OrgSpongycastlePqcAsn1XMSSPublicKey *self, IOSByteArray *publicSeed, IOSByteArray *root);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSPublicKey *new_OrgSpongycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSPublicKey *create_OrgSpongycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSPublicKey *OrgSpongycastlePqcAsn1XMSSPublicKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcAsn1XMSSPublicKey)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSPublicKey")
