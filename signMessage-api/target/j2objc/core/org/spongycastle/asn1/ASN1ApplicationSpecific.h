//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ASN1ApplicationSpecific.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1ASN1ApplicationSpecific")
#ifdef RESTRICT_OrgSpongycastleAsn1ASN1ApplicationSpecific
#define INCLUDE_ALL_OrgSpongycastleAsn1ASN1ApplicationSpecific 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1ASN1ApplicationSpecific 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1ASN1ApplicationSpecific

#if !defined (OrgSpongycastleAsn1ASN1ApplicationSpecific_) && (INCLUDE_ALL_OrgSpongycastleAsn1ASN1ApplicationSpecific || defined(INCLUDE_OrgSpongycastleAsn1ASN1ApplicationSpecific))
#define OrgSpongycastleAsn1ASN1ApplicationSpecific_

#define RESTRICT_OrgSpongycastleAsn1ASN1Primitive 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Primitive 1
#include "org/spongycastle/asn1/ASN1Primitive.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1OutputStream;

@interface OrgSpongycastleAsn1ASN1ApplicationSpecific : OrgSpongycastleAsn1ASN1Primitive {
 @public
  jboolean isConstructed_;
  jint tag_;
  IOSByteArray *octets_;
}

#pragma mark Public

- (jint)getApplicationTag;

- (IOSByteArray *)getContents;

+ (OrgSpongycastleAsn1ASN1ApplicationSpecific *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)getObject;

- (OrgSpongycastleAsn1ASN1Primitive *)getObjectWithInt:(jint)derTagNo;

- (NSUInteger)hash;

- (jboolean)isConstructed;

#pragma mark Protected

+ (jint)getLengthOfHeaderWithByteArray:(IOSByteArray *)data;

#pragma mark Package-Private

- (instancetype)initWithBoolean:(jboolean)isConstructed
                        withInt:(jint)tag
                  withByteArray:(IOSByteArray *)octets;

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o;

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1ASN1ApplicationSpecific)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1ASN1ApplicationSpecific, octets_, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1ASN1ApplicationSpecific_initWithBoolean_withInt_withByteArray_(OrgSpongycastleAsn1ASN1ApplicationSpecific *self, jboolean isConstructed, jint tag, IOSByteArray *octets);

FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ApplicationSpecific *OrgSpongycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(id obj);

FOUNDATION_EXPORT jint OrgSpongycastleAsn1ASN1ApplicationSpecific_getLengthOfHeaderWithByteArray_(IOSByteArray *data);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1ASN1ApplicationSpecific)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1ASN1ApplicationSpecific")
