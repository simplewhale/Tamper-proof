//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/LimitedInputStream.java
//

#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "org/spongycastle/asn1/IndefiniteLengthInputStream.h"
#include "org/spongycastle/asn1/LimitedInputStream.h"

@interface OrgSpongycastleAsn1LimitedInputStream () {
 @public
  jint _limit_;
}

@end

@implementation OrgSpongycastleAsn1LimitedInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                                  withInt:(jint)limit {
  OrgSpongycastleAsn1LimitedInputStream_initWithJavaIoInputStream_withInt_(self, inArg, limit);
  return self;
}

- (jint)getRemaining {
  return _limit_;
}

- (void)setParentEofDetectWithBoolean:(jboolean)on {
  if ([_in_ isKindOfClass:[OrgSpongycastleAsn1IndefiniteLengthInputStream class]]) {
    [((OrgSpongycastleAsn1IndefiniteLengthInputStream *) nil_chk(((OrgSpongycastleAsn1IndefiniteLengthInputStream *) _in_))) setEofOn00WithBoolean:on];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withInt:);
  methods[1].selector = @selector(getRemaining);
  methods[2].selector = @selector(setParentEofDetectWithBoolean:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_in_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "_limit_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;I", "setParentEofDetect", "Z" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1LimitedInputStream = { "LimitedInputStream", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x400, 3, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1LimitedInputStream;
}

@end

void OrgSpongycastleAsn1LimitedInputStream_initWithJavaIoInputStream_withInt_(OrgSpongycastleAsn1LimitedInputStream *self, JavaIoInputStream *inArg, jint limit) {
  JavaIoInputStream_init(self);
  self->_in_ = inArg;
  self->_limit_ = limit;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1LimitedInputStream)
