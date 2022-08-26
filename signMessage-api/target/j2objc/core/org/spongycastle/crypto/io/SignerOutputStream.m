//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/io/SignerOutputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/OutputStream.h"
#include "org/spongycastle/crypto/Signer.h"
#include "org/spongycastle/crypto/io/SignerOutputStream.h"

@implementation OrgSpongycastleCryptoIoSignerOutputStream

- (instancetype)initWithOrgSpongycastleCryptoSigner:(id<OrgSpongycastleCryptoSigner>)Signer {
  OrgSpongycastleCryptoIoSignerOutputStream_initWithOrgSpongycastleCryptoSigner_(self, Signer);
  return self;
}

- (void)writeWithInt:(jint)b {
  [((id<OrgSpongycastleCryptoSigner>) nil_chk(signer_)) updateWithByte:(jbyte) b];
}

- (void)writeWithByteArray:(IOSByteArray *)b
                   withInt:(jint)off
                   withInt:(jint)len {
  [((id<OrgSpongycastleCryptoSigner>) nil_chk(signer_)) updateWithByteArray:b withInt:off withInt:len];
}

- (id<OrgSpongycastleCryptoSigner>)getSigner {
  return signer_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoSigner:);
  methods[1].selector = @selector(writeWithInt:);
  methods[2].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(getSigner);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "signer_", "LOrgSpongycastleCryptoSigner;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoSigner;", "write", "I", "LJavaIoIOException;", "[BII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoIoSignerOutputStream = { "SignerOutputStream", "org.spongycastle.crypto.io", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoIoSignerOutputStream;
}

@end

void OrgSpongycastleCryptoIoSignerOutputStream_initWithOrgSpongycastleCryptoSigner_(OrgSpongycastleCryptoIoSignerOutputStream *self, id<OrgSpongycastleCryptoSigner> Signer) {
  JavaIoOutputStream_init(self);
  self->signer_ = Signer;
}

OrgSpongycastleCryptoIoSignerOutputStream *new_OrgSpongycastleCryptoIoSignerOutputStream_initWithOrgSpongycastleCryptoSigner_(id<OrgSpongycastleCryptoSigner> Signer) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoIoSignerOutputStream, initWithOrgSpongycastleCryptoSigner_, Signer)
}

OrgSpongycastleCryptoIoSignerOutputStream *create_OrgSpongycastleCryptoIoSignerOutputStream_initWithOrgSpongycastleCryptoSigner_(id<OrgSpongycastleCryptoSigner> Signer) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoIoSignerOutputStream, initWithOrgSpongycastleCryptoSigner_, Signer)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoIoSignerOutputStream)
