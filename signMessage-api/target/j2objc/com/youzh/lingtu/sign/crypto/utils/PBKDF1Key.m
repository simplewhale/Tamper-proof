//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/PBKDF1Key.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/PBKDF1Key.h"
#include "java/lang/System.h"
#include "javax/security/auth/Destroyable.h"
#include "org/spongycastle/crypto/CharToByteConverter.h"

@interface ComYouzhLingtuSignCryptoUtilsPBKDF1Key () {
 @public
  IOSCharArray *password_;
  id<OrgSpongycastleCryptoCharToByteConverter> converter_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsPBKDF1Key, password_, IOSCharArray *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsPBKDF1Key, converter_, id<OrgSpongycastleCryptoCharToByteConverter>)

@implementation ComYouzhLingtuSignCryptoUtilsPBKDF1Key

- (instancetype)initWithCharArray:(IOSCharArray *)password
withOrgSpongycastleCryptoCharToByteConverter:(id<OrgSpongycastleCryptoCharToByteConverter>)converter {
  ComYouzhLingtuSignCryptoUtilsPBKDF1Key_initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_(self, password, converter);
  return self;
}

- (IOSCharArray *)getPassword {
  return password_;
}

- (NSString *)getAlgorithm {
  return @"PBKDF1";
}

- (NSString *)getFormat {
  return [((id<OrgSpongycastleCryptoCharToByteConverter>) nil_chk(converter_)) getType];
}

- (IOSByteArray *)getEncoded {
  return [((id<OrgSpongycastleCryptoCharToByteConverter>) nil_chk(converter_)) convertWithCharArray:password_];
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[C", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withOrgSpongycastleCryptoCharToByteConverter:);
  methods[1].selector = @selector(getPassword);
  methods[2].selector = @selector(getAlgorithm);
  methods[3].selector = @selector(getFormat);
  methods[4].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "password_", "[C", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "converter_", "LOrgSpongycastleCryptoCharToByteConverter;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[CLOrgSpongycastleCryptoCharToByteConverter;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsPBKDF1Key = { "PBKDF1Key", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsPBKDF1Key;
}

@end

void ComYouzhLingtuSignCryptoUtilsPBKDF1Key_initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_(ComYouzhLingtuSignCryptoUtilsPBKDF1Key *self, IOSCharArray *password, id<OrgSpongycastleCryptoCharToByteConverter> converter) {
  NSObject_init(self);
  self->password_ = [IOSCharArray newArrayWithLength:((IOSCharArray *) nil_chk(password))->size_];
  self->converter_ = converter;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(password, 0, self->password_, 0, password->size_);
}

ComYouzhLingtuSignCryptoUtilsPBKDF1Key *new_ComYouzhLingtuSignCryptoUtilsPBKDF1Key_initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_(IOSCharArray *password, id<OrgSpongycastleCryptoCharToByteConverter> converter) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPBKDF1Key, initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_, password, converter)
}

ComYouzhLingtuSignCryptoUtilsPBKDF1Key *create_ComYouzhLingtuSignCryptoUtilsPBKDF1Key_initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_(IOSCharArray *password, id<OrgSpongycastleCryptoCharToByteConverter> converter) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPBKDF1Key, initWithCharArray_withOrgSpongycastleCryptoCharToByteConverter_, password, converter)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsPBKDF1Key)
