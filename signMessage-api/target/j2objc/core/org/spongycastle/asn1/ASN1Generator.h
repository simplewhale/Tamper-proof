//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ASN1Generator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1ASN1Generator")
#ifdef RESTRICT_OrgSpongycastleAsn1ASN1Generator
#define INCLUDE_ALL_OrgSpongycastleAsn1ASN1Generator 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1ASN1Generator 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1ASN1Generator

#if !defined (OrgSpongycastleAsn1ASN1Generator_) && (INCLUDE_ALL_OrgSpongycastleAsn1ASN1Generator || defined(INCLUDE_OrgSpongycastleAsn1ASN1Generator))
#define OrgSpongycastleAsn1ASN1Generator_

@class JavaIoOutputStream;

@interface OrgSpongycastleAsn1ASN1Generator : NSObject {
 @public
  JavaIoOutputStream *_out_;
}

#pragma mark Public

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (JavaIoOutputStream *)getRawOutputStream;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1ASN1Generator)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1ASN1Generator, _out_, JavaIoOutputStream *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1ASN1Generator_initWithJavaIoOutputStream_(OrgSpongycastleAsn1ASN1Generator *self, JavaIoOutputStream *outArg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1ASN1Generator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1ASN1Generator")
