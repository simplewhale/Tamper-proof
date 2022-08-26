//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BEROutputStream.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/io/OutputStream.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/BEROutputStream.h"
#include "org/spongycastle/asn1/DEROutputStream.h"

@implementation OrgSpongycastleAsn1BEROutputStream

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)os {
  OrgSpongycastleAsn1BEROutputStream_initWithJavaIoOutputStream_(self, os);
  return self;
}

- (void)writeObjectWithId:(id)obj {
  if (obj == nil) {
    [self writeNull];
  }
  else if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1Primitive class]]) {
    [((OrgSpongycastleAsn1ASN1Primitive *) obj) encodeWithOrgSpongycastleAsn1ASN1OutputStream:self];
  }
  else if ([OrgSpongycastleAsn1ASN1Encodable_class_() isInstance:obj]) {
    [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk([((id<OrgSpongycastleAsn1ASN1Encodable>) cast_check(obj, OrgSpongycastleAsn1ASN1Encodable_class_())) toASN1Primitive])) encodeWithOrgSpongycastleAsn1ASN1OutputStream:self];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"object not BEREncodable");
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:);
  methods[1].selector = @selector(writeObjectWithId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoOutputStream;", "writeObject", "LNSObject;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1BEROutputStream = { "BEROutputStream", "org.spongycastle.asn1", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1BEROutputStream;
}

@end

void OrgSpongycastleAsn1BEROutputStream_initWithJavaIoOutputStream_(OrgSpongycastleAsn1BEROutputStream *self, JavaIoOutputStream *os) {
  OrgSpongycastleAsn1DEROutputStream_initWithJavaIoOutputStream_(self, os);
}

OrgSpongycastleAsn1BEROutputStream *new_OrgSpongycastleAsn1BEROutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BEROutputStream, initWithJavaIoOutputStream_, os)
}

OrgSpongycastleAsn1BEROutputStream *create_OrgSpongycastleAsn1BEROutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BEROutputStream, initWithJavaIoOutputStream_, os)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1BEROutputStream)