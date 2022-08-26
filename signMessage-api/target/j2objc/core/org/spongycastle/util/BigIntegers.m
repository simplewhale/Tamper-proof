//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/BigIntegers.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/util/BigIntegers.h"

inline jint OrgSpongycastleUtilBigIntegers_get_MAX_ITERATIONS(void);
#define OrgSpongycastleUtilBigIntegers_MAX_ITERATIONS 1000
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleUtilBigIntegers, MAX_ITERATIONS, jint)

inline JavaMathBigInteger *OrgSpongycastleUtilBigIntegers_get_ZERO(void);
static JavaMathBigInteger *OrgSpongycastleUtilBigIntegers_ZERO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleUtilBigIntegers, ZERO, JavaMathBigInteger *)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleUtilBigIntegers)

@implementation OrgSpongycastleUtilBigIntegers

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleUtilBigIntegers_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)asUnsignedByteArrayWithJavaMathBigInteger:(JavaMathBigInteger *)value {
  return OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(value);
}

+ (IOSByteArray *)asUnsignedByteArrayWithInt:(jint)length
                      withJavaMathBigInteger:(JavaMathBigInteger *)value {
  return OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(length, value);
}

+ (JavaMathBigInteger *)createRandomInRangeWithJavaMathBigInteger:(JavaMathBigInteger *)min
                                           withJavaMathBigInteger:(JavaMathBigInteger *)max
                                     withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(min, max, random);
}

+ (JavaMathBigInteger *)fromUnsignedByteArrayWithByteArray:(IOSByteArray *)buf {
  return OrgSpongycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_(buf);
}

+ (JavaMathBigInteger *)fromUnsignedByteArrayWithByteArray:(IOSByteArray *)buf
                                                   withInt:(jint)off
                                                   withInt:(jint)length {
  return OrgSpongycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_withInt_withInt_(buf, off, length);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 5, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(asUnsignedByteArrayWithJavaMathBigInteger:);
  methods[2].selector = @selector(asUnsignedByteArrayWithInt:withJavaMathBigInteger:);
  methods[3].selector = @selector(createRandomInRangeWithJavaMathBigInteger:withJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(fromUnsignedByteArrayWithByteArray:);
  methods[5].selector = @selector(fromUnsignedByteArrayWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MAX_ITERATIONS", "I", .constantValue.asInt = OrgSpongycastleUtilBigIntegers_MAX_ITERATIONS, 0x1a, -1, -1, -1, -1 },
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
  };
  static const void *ptrTable[] = { "asUnsignedByteArray", "LJavaMathBigInteger;", "ILJavaMathBigInteger;", "createRandomInRange", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaSecuritySecureRandom;", "fromUnsignedByteArray", "[B", "[BII", &OrgSpongycastleUtilBigIntegers_ZERO };
  static const J2ObjcClassInfo _OrgSpongycastleUtilBigIntegers = { "BigIntegers", "org.spongycastle.util", ptrTable, methods, fields, 7, 0x11, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilBigIntegers;
}

+ (void)initialize {
  if (self == [OrgSpongycastleUtilBigIntegers class]) {
    OrgSpongycastleUtilBigIntegers_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleUtilBigIntegers)
  }
}

@end

void OrgSpongycastleUtilBigIntegers_init(OrgSpongycastleUtilBigIntegers *self) {
  NSObject_init(self);
}

OrgSpongycastleUtilBigIntegers *new_OrgSpongycastleUtilBigIntegers_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilBigIntegers, init)
}

OrgSpongycastleUtilBigIntegers *create_OrgSpongycastleUtilBigIntegers_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilBigIntegers, init)
}

IOSByteArray *OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  OrgSpongycastleUtilBigIntegers_initialize();
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(value)) toByteArray];
  if (IOSByteArray_Get(nil_chk(bytes), 0) == 0) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:bytes->size_ - 1];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, 1, tmp, 0, tmp->size_);
    return tmp;
  }
  return bytes;
}

IOSByteArray *OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(jint length, JavaMathBigInteger *value) {
  OrgSpongycastleUtilBigIntegers_initialize();
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(value)) toByteArray];
  if (((IOSByteArray *) nil_chk(bytes))->size_ == length) {
    return bytes;
  }
  jint start = IOSByteArray_Get(bytes, 0) == 0 ? 1 : 0;
  jint count = bytes->size_ - start;
  if (count > length) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"standard length exceeded for value");
  }
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:length];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, start, tmp, tmp->size_ - count, count);
  return tmp;
}

JavaMathBigInteger *OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *min, JavaMathBigInteger *max, JavaSecuritySecureRandom *random) {
  OrgSpongycastleUtilBigIntegers_initialize();
  jint cmp = [((JavaMathBigInteger *) nil_chk(min)) compareToWithId:max];
  if (cmp >= 0) {
    if (cmp > 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'min' may not be greater than 'max'");
    }
    return min;
  }
  if ([min bitLength] > [((JavaMathBigInteger *) nil_chk(max)) bitLength] / 2) {
    return [((JavaMathBigInteger *) nil_chk(OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleUtilBigIntegers_ZERO, [max subtractWithJavaMathBigInteger:min], random))) addWithJavaMathBigInteger:min];
  }
  for (jint i = 0; i < OrgSpongycastleUtilBigIntegers_MAX_ITERATIONS; ++i) {
    JavaMathBigInteger *x = new_JavaMathBigInteger_initWithInt_withJavaUtilRandom_([max bitLength], random);
    if ([x compareToWithId:min] >= 0 && [x compareToWithId:max] <= 0) {
      return x;
    }
  }
  return [new_JavaMathBigInteger_initWithInt_withJavaUtilRandom_([((JavaMathBigInteger *) nil_chk([max subtractWithJavaMathBigInteger:min])) bitLength] - 1, random) addWithJavaMathBigInteger:min];
}

JavaMathBigInteger *OrgSpongycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_(IOSByteArray *buf) {
  OrgSpongycastleUtilBigIntegers_initialize();
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, buf);
}

JavaMathBigInteger *OrgSpongycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_withInt_withInt_(IOSByteArray *buf, jint off, jint length) {
  OrgSpongycastleUtilBigIntegers_initialize();
  IOSByteArray *mag = buf;
  if (off != 0 || length != ((IOSByteArray *) nil_chk(buf))->size_) {
    mag = [IOSByteArray newArrayWithLength:length];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, mag, 0, length);
  }
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, mag);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilBigIntegers)
