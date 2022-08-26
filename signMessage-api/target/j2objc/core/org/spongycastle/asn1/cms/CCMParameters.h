//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/CCMParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsCCMParameters")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsCCMParameters
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsCCMParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsCCMParameters 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsCCMParameters

#if !defined (OrgSpongycastleAsn1CmsCCMParameters_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsCCMParameters || defined(INCLUDE_OrgSpongycastleAsn1CmsCCMParameters))
#define OrgSpongycastleAsn1CmsCCMParameters_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1CmsCCMParameters : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)nonce
                          withInt:(jint)icvLen;

- (jint)getIcvLen;

+ (OrgSpongycastleAsn1CmsCCMParameters *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getNonce;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsCCMParameters)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsCCMParameters *OrgSpongycastleAsn1CmsCCMParameters_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsCCMParameters_initWithByteArray_withInt_(OrgSpongycastleAsn1CmsCCMParameters *self, IOSByteArray *nonce, jint icvLen);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsCCMParameters *new_OrgSpongycastleAsn1CmsCCMParameters_initWithByteArray_withInt_(IOSByteArray *nonce, jint icvLen) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsCCMParameters *create_OrgSpongycastleAsn1CmsCCMParameters_initWithByteArray_withInt_(IOSByteArray *nonce, jint icvLen);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsCCMParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsCCMParameters")
