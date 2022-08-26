//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/Poly1305KeyGenerator.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherKeyGenerator.h"
#include "org/spongycastle/crypto/KeyGenerationParameters.h"
#include "org/spongycastle/crypto/generators/Poly1305KeyGenerator.h"

@interface OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator ()

+ (void)checkMaskWithByte:(jbyte)b
                 withByte:(jbyte)mask;

@end

inline jbyte OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_get_R_MASK_LOW_2(void);
#define OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2 -4
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator, R_MASK_LOW_2, jbyte)

inline jbyte OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_get_R_MASK_HIGH_4(void);
#define OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4 15
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator, R_MASK_HIGH_4, jbyte)

__attribute__((unused)) static void OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(jbyte b, jbyte mask);

@implementation OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param {
  [super init__WithOrgSpongycastleCryptoKeyGenerationParameters:new_OrgSpongycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_([((OrgSpongycastleCryptoKeyGenerationParameters *) nil_chk(param)) getRandom], 256)];
}

- (IOSByteArray *)generateKey {
  IOSByteArray *key = [super generateKey];
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_clampWithByteArray_(key);
  return key;
}

+ (void)clampWithByteArray:(IOSByteArray *)key {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_clampWithByteArray_(key);
}

+ (void)checkKeyWithByteArray:(IOSByteArray *)key {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkKeyWithByteArray_(key);
}

+ (void)checkMaskWithByte:(jbyte)b
                 withByte:(jbyte)mask {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(b, mask);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 4, 3, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithOrgSpongycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKey);
  methods[3].selector = @selector(clampWithByteArray:);
  methods[4].selector = @selector(checkKeyWithByteArray:);
  methods[5].selector = @selector(checkMaskWithByte:withByte:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "R_MASK_LOW_2", "B", .constantValue.asChar = OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2, 0x1a, -1, -1, -1, -1 },
    { "R_MASK_HIGH_4", "B", .constantValue.asChar = OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LOrgSpongycastleCryptoKeyGenerationParameters;", "clamp", "[B", "checkKey", "checkMask", "BB" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator = { "Poly1305KeyGenerator", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator;
}

@end

void OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_init(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator *self) {
  OrgSpongycastleCryptoCipherKeyGenerator_init(self);
}

OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator *new_OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator, init)
}

OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator *create_OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator, init)
}

void OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_clampWithByteArray_(IOSByteArray *key) {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_initialize();
  if (((IOSByteArray *) nil_chk(key))->size_ != 32) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Poly1305 key must be 256 bits.");
  }
  *IOSByteArray_GetRef(key, 3) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4;
  *IOSByteArray_GetRef(key, 7) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4;
  *IOSByteArray_GetRef(key, 11) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4;
  *IOSByteArray_GetRef(key, 15) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4;
  *IOSByteArray_GetRef(key, 4) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2;
  *IOSByteArray_GetRef(key, 8) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2;
  *IOSByteArray_GetRef(key, 12) &= OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2;
}

void OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkKeyWithByteArray_(IOSByteArray *key) {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_initialize();
  if (((IOSByteArray *) nil_chk(key))->size_ != 32) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Poly1305 key must be 256 bits.");
  }
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 3), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 7), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 11), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 15), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_HIGH_4);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 4), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 8), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2);
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(IOSByteArray_Get(key, 12), OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_R_MASK_LOW_2);
}

void OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_checkMaskWithByte_withByte_(jbyte b, jbyte mask) {
  OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator_initialize();
  if ((b & (~mask)) != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid format for r portion of Poly1305 key.");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsPoly1305KeyGenerator)
