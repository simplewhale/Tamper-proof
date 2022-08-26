//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/X509NameEntryConverter.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1InputStream.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/DERPrintableString.h"
#include "org/spongycastle/asn1/x509/X509NameEntryConverter.h"
#include "org/spongycastle/util/Strings.h"

@implementation OrgSpongycastleAsn1X509X509NameEntryConverter

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1X509X509NameEntryConverter_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastleAsn1ASN1Primitive *)convertHexEncodedWithNSString:(NSString *)str
                                                            withInt:(jint)off {
  str = OrgSpongycastleUtilStrings_toLowerCaseWithNSString_(str);
  IOSByteArray *data = [IOSByteArray newArrayWithLength:([((NSString *) nil_chk(str)) java_length] - off) / 2];
  for (jint index = 0; index != data->size_; index++) {
    jchar left = [str charAtWithInt:(index * 2) + off];
    jchar right = [str charAtWithInt:(index * 2) + off + 1];
    if (left < 'a') {
      *IOSByteArray_GetRef(data, index) = (jbyte) (JreLShift32((left - '0'), 4));
    }
    else {
      *IOSByteArray_GetRef(data, index) = (jbyte) (JreLShift32((left - 'a' + 10), 4));
    }
    if (right < 'a') {
      *IOSByteArray_GetRef(data, index) |= (jbyte) (right - '0');
    }
    else {
      *IOSByteArray_GetRef(data, index) |= (jbyte) (right - 'a' + 10);
    }
  }
  OrgSpongycastleAsn1ASN1InputStream *aIn = new_OrgSpongycastleAsn1ASN1InputStream_initWithByteArray_(data);
  return [aIn readObject];
}

- (jboolean)canBePrintableWithNSString:(NSString *)str {
  return OrgSpongycastleAsn1DERPrintableString_isPrintableStringWithNSString_(str);
}

- (OrgSpongycastleAsn1ASN1Primitive *)getConvertedValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                      withNSString:(NSString *)value {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "Z", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x401, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(convertHexEncodedWithNSString:withInt:);
  methods[2].selector = @selector(canBePrintableWithNSString:);
  methods[3].selector = @selector(getConvertedValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "convertHexEncoded", "LNSString;I", "LJavaIoIOException;", "canBePrintable", "LNSString;", "getConvertedValue", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LNSString;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509X509NameEntryConverter = { "X509NameEntryConverter", "org.spongycastle.asn1.x509", ptrTable, methods, NULL, 7, 0x401, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509X509NameEntryConverter;
}

@end

void OrgSpongycastleAsn1X509X509NameEntryConverter_init(OrgSpongycastleAsn1X509X509NameEntryConverter *self) {
  NSObject_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509X509NameEntryConverter)
