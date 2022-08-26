//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/io/MacOutputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/OutputStream.h"
#include "org/spongycastle/crypto/Mac.h"
#include "org/spongycastle/crypto/io/MacOutputStream.h"

@implementation OrgSpongycastleCryptoIoMacOutputStream

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac {
  OrgSpongycastleCryptoIoMacOutputStream_initWithOrgSpongycastleCryptoMac_(self, mac);
  return self;
}

- (void)writeWithInt:(jint)b {
  [((id<OrgSpongycastleCryptoMac>) nil_chk(mac_)) updateWithByte:(jbyte) b];
}

- (void)writeWithByteArray:(IOSByteArray *)b
                   withInt:(jint)off
                   withInt:(jint)len {
  [((id<OrgSpongycastleCryptoMac>) nil_chk(mac_)) updateWithByteArray:b withInt:off withInt:len];
}

- (IOSByteArray *)getMac {
  IOSByteArray *res = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoMac>) nil_chk(mac_)) getMacSize]];
  [((id<OrgSpongycastleCryptoMac>) nil_chk(mac_)) doFinalWithByteArray:res withInt:0];
  return res;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoMac:);
  methods[1].selector = @selector(writeWithInt:);
  methods[2].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(getMac);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "mac_", "LOrgSpongycastleCryptoMac;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoMac;", "write", "I", "LJavaIoIOException;", "[BII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoIoMacOutputStream = { "MacOutputStream", "org.spongycastle.crypto.io", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoIoMacOutputStream;
}

@end

void OrgSpongycastleCryptoIoMacOutputStream_initWithOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoIoMacOutputStream *self, id<OrgSpongycastleCryptoMac> mac) {
  JavaIoOutputStream_init(self);
  self->mac_ = mac;
}

OrgSpongycastleCryptoIoMacOutputStream *new_OrgSpongycastleCryptoIoMacOutputStream_initWithOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoMac> mac) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoIoMacOutputStream, initWithOrgSpongycastleCryptoMac_, mac)
}

OrgSpongycastleCryptoIoMacOutputStream *create_OrgSpongycastleCryptoIoMacOutputStream_initWithOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoMac> mac) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoIoMacOutputStream, initWithOrgSpongycastleCryptoMac_, mac)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoIoMacOutputStream)
