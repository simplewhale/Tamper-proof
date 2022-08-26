//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsInputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "org/spongycastle/crypto/tls/TlsInputStream.h"
#include "org/spongycastle/crypto/tls/TlsProtocol.h"

@interface OrgSpongycastleCryptoTlsTlsInputStream () {
 @public
  IOSByteArray *buf_;
  OrgSpongycastleCryptoTlsTlsProtocol *handler_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsTlsInputStream, buf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsTlsInputStream, handler_, OrgSpongycastleCryptoTlsTlsProtocol *)

@implementation OrgSpongycastleCryptoTlsTlsInputStream

- (instancetype)initWithOrgSpongycastleCryptoTlsTlsProtocol:(OrgSpongycastleCryptoTlsTlsProtocol *)handler {
  OrgSpongycastleCryptoTlsTlsInputStream_initWithOrgSpongycastleCryptoTlsTlsProtocol_(self, handler);
  return self;
}

- (jint)available {
  return [((OrgSpongycastleCryptoTlsTlsProtocol *) nil_chk(self->handler_)) applicationDataAvailable];
}

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)offset
                  withInt:(jint)len {
  return [((OrgSpongycastleCryptoTlsTlsProtocol *) nil_chk(self->handler_)) readApplicationDataWithByteArray:buf withInt:offset withInt:len];
}

- (jint)read {
  if ([self readWithByteArray:buf_] < 0) {
    return -1;
  }
  return IOSByteArray_Get(nil_chk(buf_), 0) & (jint) 0xff;
}

- (void)close {
  [((OrgSpongycastleCryptoTlsTlsProtocol *) nil_chk(handler_)) close];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoTlsTlsProtocol:);
  methods[1].selector = @selector(available);
  methods[2].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(read);
  methods[4].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "handler_", "LOrgSpongycastleCryptoTlsTlsProtocol;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoTlsTlsProtocol;", "LJavaIoIOException;", "read", "[BII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsInputStream = { "TlsInputStream", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x0, 5, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsInputStream;
}

@end

void OrgSpongycastleCryptoTlsTlsInputStream_initWithOrgSpongycastleCryptoTlsTlsProtocol_(OrgSpongycastleCryptoTlsTlsInputStream *self, OrgSpongycastleCryptoTlsTlsProtocol *handler) {
  JavaIoInputStream_init(self);
  self->buf_ = [IOSByteArray newArrayWithLength:1];
  self->handler_ = nil;
  self->handler_ = handler;
}

OrgSpongycastleCryptoTlsTlsInputStream *new_OrgSpongycastleCryptoTlsTlsInputStream_initWithOrgSpongycastleCryptoTlsTlsProtocol_(OrgSpongycastleCryptoTlsTlsProtocol *handler) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsInputStream, initWithOrgSpongycastleCryptoTlsTlsProtocol_, handler)
}

OrgSpongycastleCryptoTlsTlsInputStream *create_OrgSpongycastleCryptoTlsTlsInputStream_initWithOrgSpongycastleCryptoTlsTlsProtocol_(OrgSpongycastleCryptoTlsTlsProtocol *handler) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsInputStream, initWithOrgSpongycastleCryptoTlsTlsProtocol_, handler)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsInputStream)