//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/asn1/XMSSMTPublicKey.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSMTPublicKey")
#ifdef RESTRICT_OrgSpongycastlePqcAsn1XMSSMTPublicKey
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSMTPublicKey 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSMTPublicKey 1
#endif
#undef RESTRICT_OrgSpongycastlePqcAsn1XMSSMTPublicKey

#if !defined (OrgSpongycastlePqcAsn1XMSSMTPublicKey_) && (INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSMTPublicKey || defined(INCLUDE_OrgSpongycastlePqcAsn1XMSSMTPublicKey))
#define OrgSpongycastlePqcAsn1XMSSMTPublicKey_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastlePqcAsn1XMSSMTPublicKey : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)publicSeed
                    withByteArray:(IOSByteArray *)root;

+ (OrgSpongycastlePqcAsn1XMSSMTPublicKey *)getInstanceWithId:(id)o;

- (IOSByteArray *)getPublicSeed;

- (IOSByteArray *)getRoot;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcAsn1XMSSMTPublicKey)

FOUNDATION_EXPORT void OrgSpongycastlePqcAsn1XMSSMTPublicKey_initWithByteArray_withByteArray_(OrgSpongycastlePqcAsn1XMSSMTPublicKey *self, IOSByteArray *publicSeed, IOSByteArray *root);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSMTPublicKey *new_OrgSpongycastlePqcAsn1XMSSMTPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSMTPublicKey *create_OrgSpongycastlePqcAsn1XMSSMTPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1XMSSMTPublicKey *OrgSpongycastlePqcAsn1XMSSMTPublicKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcAsn1XMSSMTPublicKey)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1XMSSMTPublicKey")
