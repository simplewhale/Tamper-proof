//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/io/SimpleOutputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/OutputStream.h"
#include "org/spongycastle/util/io/SimpleOutputStream.h"

@implementation OrgSpongycastleUtilIoSimpleOutputStream

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleUtilIoSimpleOutputStream_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)close {
}

- (void)flush {
}

- (void)writeWithInt:(jint)b {
  IOSByteArray *buf = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) b } count:1];
  [self writeWithByteArray:buf withInt:0 withInt:1];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(close);
  methods[2].selector = @selector(flush);
  methods[3].selector = @selector(writeWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "write", "I", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilIoSimpleOutputStream = { "SimpleOutputStream", "org.spongycastle.util.io", ptrTable, methods, NULL, 7, 0x401, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilIoSimpleOutputStream;
}

@end

void OrgSpongycastleUtilIoSimpleOutputStream_init(OrgSpongycastleUtilIoSimpleOutputStream *self) {
  JavaIoOutputStream_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilIoSimpleOutputStream)
