//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/SerpentEngineBase.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/engines/SerpentEngineBase.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"

@implementation OrgSpongycastleCryptoEnginesSerpentEngineBase

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEnginesSerpentEngineBase_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)encrypting
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  if ([params isKindOfClass:[OrgSpongycastleCryptoParamsKeyParameter class]]) {
    self->encrypting_ = encrypting;
    self->wKey_ = [self makeWorkingKeyWithByteArray:[((OrgSpongycastleCryptoParamsKeyParameter *) nil_chk(((OrgSpongycastleCryptoParamsKeyParameter *) params))) getKey]];
    return;
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$$$", @"invalid parameter passed to ", [self getAlgorithmName], @" init - ", [[((id<OrgSpongycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
}

- (NSString *)getAlgorithmName {
  return @"Serpent";
}

- (jint)getBlockSize {
  return OrgSpongycastleCryptoEnginesSerpentEngineBase_BLOCK_SIZE;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (wKey_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" not initialised"));
  }
  if ((inOff + OrgSpongycastleCryptoEnginesSerpentEngineBase_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + OrgSpongycastleCryptoEnginesSerpentEngineBase_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (encrypting_) {
    [self encryptBlockWithByteArray:inArg withInt:inOff withByteArray:outArg withInt:outOff];
  }
  else {
    [self decryptBlockWithByteArray:inArg withInt:inOff withByteArray:outArg withInt:outOff];
  }
  return OrgSpongycastleCryptoEnginesSerpentEngineBase_BLOCK_SIZE;
}

- (void)reset {
}

+ (jint)rotateLeftWithInt:(jint)x
                  withInt:(jint)bits {
  return OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(x, bits);
}

+ (jint)rotateRightWithInt:(jint)x
                   withInt:(jint)bits {
  return OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(x, bits);
}

- (void)sb0WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = a ^ d;
  jint t3 = c ^ t1;
  jint t4 = b ^ t3;
  X3_ = (a & d) ^ t4;
  jint t7 = a ^ (b & t1);
  X2_ = t4 ^ (c | t7);
  jint t12 = X3_ & (t3 ^ t7);
  X1_ = (~t3) ^ t12;
  X0_ = t12 ^ (~t7);
}

- (void)ib0WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~a;
  jint t2 = a ^ b;
  jint t4 = d ^ (t1 | t2);
  jint t5 = c ^ t4;
  X2_ = t2 ^ t5;
  jint t8 = t1 ^ (d & t2);
  X1_ = t4 ^ (X2_ & t8);
  X3_ = (a & t4) ^ (t5 | X1_);
  X0_ = X3_ ^ (t5 ^ t8);
}

- (void)sb1WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t2 = b ^ (~a);
  jint t5 = c ^ (a | t2);
  X2_ = d ^ t5;
  jint t7 = b ^ (d | t2);
  jint t8 = t2 ^ X2_;
  X3_ = t8 ^ (t5 & t7);
  jint t11 = t5 ^ t7;
  X1_ = X3_ ^ t11;
  X0_ = t5 ^ (t8 & t11);
}

- (void)ib1WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = b ^ d;
  jint t3 = a ^ (b & t1);
  jint t4 = t1 ^ t3;
  X3_ = c ^ t4;
  jint t7 = b ^ (t1 & t3);
  jint t8 = X3_ | t7;
  X1_ = t3 ^ t8;
  jint t10 = ~X1_;
  jint t11 = X3_ ^ t7;
  X0_ = t10 ^ t11;
  X2_ = t4 ^ (t10 | t11);
}

- (void)sb2WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~a;
  jint t2 = b ^ d;
  jint t3 = c & t1;
  X0_ = t2 ^ t3;
  jint t5 = c ^ t1;
  jint t6 = c ^ X0_;
  jint t7 = b & t6;
  X3_ = t5 ^ t7;
  X2_ = a ^ ((d | t7) & (X0_ | t5));
  X1_ = (t2 ^ X3_) ^ (X2_ ^ (d | t1));
}

- (void)ib2WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = b ^ d;
  jint t2 = ~t1;
  jint t3 = a ^ c;
  jint t4 = c ^ t1;
  jint t5 = b & t4;
  X0_ = t3 ^ t5;
  jint t7 = a | t2;
  jint t8 = d ^ t7;
  jint t9 = t3 | t8;
  X3_ = t1 ^ t9;
  jint t11 = ~t4;
  jint t12 = X0_ | X3_;
  X1_ = t11 ^ t12;
  X2_ = (d & t11) ^ (t3 ^ t12);
}

- (void)sb3WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = a ^ b;
  jint t2 = a & c;
  jint t3 = a | d;
  jint t4 = c ^ d;
  jint t5 = t1 & t3;
  jint t6 = t2 | t5;
  X2_ = t4 ^ t6;
  jint t8 = b ^ t3;
  jint t9 = t6 ^ t8;
  jint t10 = t4 & t9;
  X0_ = t1 ^ t10;
  jint t12 = X2_ & X0_;
  X1_ = t9 ^ t12;
  X3_ = (b | d) ^ (t4 ^ t12);
}

- (void)ib3WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = a | b;
  jint t2 = b ^ c;
  jint t3 = b & t2;
  jint t4 = a ^ t3;
  jint t5 = c ^ t4;
  jint t6 = d | t4;
  X0_ = t2 ^ t6;
  jint t8 = t2 | t6;
  jint t9 = d ^ t8;
  X2_ = t5 ^ t9;
  jint t11 = t1 ^ t9;
  jint t12 = X0_ & t11;
  X3_ = t4 ^ t12;
  X1_ = X3_ ^ (X0_ ^ t11);
}

- (void)sb4WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = a ^ d;
  jint t2 = d & t1;
  jint t3 = c ^ t2;
  jint t4 = b | t3;
  X3_ = t1 ^ t4;
  jint t6 = ~b;
  jint t7 = t1 | t6;
  X0_ = t3 ^ t7;
  jint t9 = a & X0_;
  jint t10 = t1 ^ t6;
  jint t11 = t4 & t10;
  X2_ = t9 ^ t11;
  X1_ = (a ^ t3) ^ (t10 & X2_);
}

- (void)ib4WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = c | d;
  jint t2 = a & t1;
  jint t3 = b ^ t2;
  jint t4 = a & t3;
  jint t5 = c ^ t4;
  X1_ = d ^ t5;
  jint t7 = ~a;
  jint t8 = t5 & X1_;
  X3_ = t3 ^ t8;
  jint t10 = X1_ | t7;
  jint t11 = d ^ t10;
  X0_ = X3_ ^ t11;
  X2_ = (t3 & t11) ^ (X1_ ^ t7);
}

- (void)sb5WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~a;
  jint t2 = a ^ b;
  jint t3 = a ^ d;
  jint t4 = c ^ t1;
  jint t5 = t2 | t3;
  X0_ = t4 ^ t5;
  jint t7 = d & X0_;
  jint t8 = t2 ^ X0_;
  X1_ = t7 ^ t8;
  jint t10 = t1 | X0_;
  jint t11 = t2 | t7;
  jint t12 = t3 ^ t10;
  X2_ = t11 ^ t12;
  X3_ = (b ^ t7) ^ (X1_ & t12);
}

- (void)ib5WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~c;
  jint t2 = b & t1;
  jint t3 = d ^ t2;
  jint t4 = a & t3;
  jint t5 = b ^ t1;
  X3_ = t4 ^ t5;
  jint t7 = b | X3_;
  jint t8 = a & t7;
  X1_ = t3 ^ t8;
  jint t10 = a | d;
  jint t11 = t1 ^ t7;
  X0_ = t10 ^ t11;
  X2_ = (b & t10) ^ (t4 | (a ^ c));
}

- (void)sb6WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~a;
  jint t2 = a ^ d;
  jint t3 = b ^ t2;
  jint t4 = t1 | t2;
  jint t5 = c ^ t4;
  X1_ = b ^ t5;
  jint t7 = t2 | X1_;
  jint t8 = d ^ t7;
  jint t9 = t5 & t8;
  X2_ = t3 ^ t9;
  jint t11 = t5 ^ t8;
  X0_ = X2_ ^ t11;
  X3_ = (~t5) ^ (t3 & t11);
}

- (void)ib6WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = ~a;
  jint t2 = a ^ b;
  jint t3 = c ^ t2;
  jint t4 = c | t1;
  jint t5 = d ^ t4;
  X1_ = t3 ^ t5;
  jint t7 = t3 & t5;
  jint t8 = t2 ^ t7;
  jint t9 = b | t8;
  X3_ = t5 ^ t9;
  jint t11 = b | X3_;
  X0_ = t8 ^ t11;
  X2_ = (d & t1) ^ (t3 ^ t11);
}

- (void)sb7WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t1 = b ^ c;
  jint t2 = c & t1;
  jint t3 = d ^ t2;
  jint t4 = a ^ t3;
  jint t5 = d | t1;
  jint t6 = t4 & t5;
  X1_ = b ^ t6;
  jint t8 = t3 | X1_;
  jint t9 = a & t4;
  X3_ = t1 ^ t9;
  jint t11 = t4 ^ t8;
  jint t12 = X3_ & t11;
  X2_ = t3 ^ t12;
  X0_ = (~t11) ^ (X3_ & X2_);
}

- (void)ib7WithInt:(jint)a
           withInt:(jint)b
           withInt:(jint)c
           withInt:(jint)d {
  jint t3 = c | (a & b);
  jint t4 = d & (a | b);
  X3_ = t3 ^ t4;
  jint t6 = ~d;
  jint t7 = b ^ t4;
  jint t9 = t7 | (X3_ ^ t6);
  X1_ = a ^ t9;
  X0_ = (c ^ t7) ^ (d | X1_);
  X2_ = (t3 ^ X1_) ^ (X0_ ^ (a & X3_));
}

- (void)LT {
  jint x0 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(X0_, 13);
  jint x2 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(X2_, 3);
  jint x1 = X1_ ^ x0 ^ x2;
  jint x3 = X3_ ^ x2 ^ JreLShift32(x0, 3);
  X1_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(x1, 1);
  X3_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(x3, 7);
  X0_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(x0 ^ X1_ ^ X3_, 5);
  X2_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(x2 ^ X3_ ^ (JreLShift32(X1_, 7)), 22);
}

- (void)inverseLT {
  jint x2 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(X2_, 22) ^ X3_ ^ (JreLShift32(X1_, 7));
  jint x0 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(X0_, 5) ^ X1_ ^ X3_;
  jint x3 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(X3_, 7);
  jint x1 = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(X1_, 1);
  X3_ = x3 ^ x2 ^ JreLShift32(x0, 3);
  X1_ = x1 ^ x0 ^ x2;
  X2_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(x2, 3);
  X0_ = OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(x0, 13);
}

- (IOSIntArray *)makeWorkingKeyWithByteArray:(IOSByteArray *)key {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (void)encryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)decryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x11, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 6, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 9, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 10, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 11, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 12, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 13, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 14, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 15, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 16, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 17, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 18, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 19, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 20, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 21, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 22, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 23, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x14, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x14, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x404, 24, 25, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 26, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 27, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(reset);
  methods[6].selector = @selector(rotateLeftWithInt:withInt:);
  methods[7].selector = @selector(rotateRightWithInt:withInt:);
  methods[8].selector = @selector(sb0WithInt:withInt:withInt:withInt:);
  methods[9].selector = @selector(ib0WithInt:withInt:withInt:withInt:);
  methods[10].selector = @selector(sb1WithInt:withInt:withInt:withInt:);
  methods[11].selector = @selector(ib1WithInt:withInt:withInt:withInt:);
  methods[12].selector = @selector(sb2WithInt:withInt:withInt:withInt:);
  methods[13].selector = @selector(ib2WithInt:withInt:withInt:withInt:);
  methods[14].selector = @selector(sb3WithInt:withInt:withInt:withInt:);
  methods[15].selector = @selector(ib3WithInt:withInt:withInt:withInt:);
  methods[16].selector = @selector(sb4WithInt:withInt:withInt:withInt:);
  methods[17].selector = @selector(ib4WithInt:withInt:withInt:withInt:);
  methods[18].selector = @selector(sb5WithInt:withInt:withInt:withInt:);
  methods[19].selector = @selector(ib5WithInt:withInt:withInt:withInt:);
  methods[20].selector = @selector(sb6WithInt:withInt:withInt:withInt:);
  methods[21].selector = @selector(ib6WithInt:withInt:withInt:withInt:);
  methods[22].selector = @selector(sb7WithInt:withInt:withInt:withInt:);
  methods[23].selector = @selector(ib7WithInt:withInt:withInt:withInt:);
  methods[24].selector = @selector(LT);
  methods[25].selector = @selector(inverseLT);
  methods[26].selector = @selector(makeWorkingKeyWithByteArray:);
  methods[27].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[28].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BLOCK_SIZE", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesSerpentEngineBase_BLOCK_SIZE, 0x1c, -1, -1, -1, -1 },
    { "ROUNDS", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesSerpentEngineBase_ROUNDS, 0x18, -1, -1, -1, -1 },
    { "PHI", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesSerpentEngineBase_PHI, 0x18, -1, -1, -1, -1 },
    { "encrypting_", "Z", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "wKey_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "X0_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "X1_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "X2_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "X3_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "processBlock", "[BI[BI", "rotateLeft", "II", "rotateRight", "sb0", "IIII", "ib0", "sb1", "ib1", "sb2", "ib2", "sb3", "ib3", "sb4", "ib4", "sb5", "ib5", "sb6", "ib6", "sb7", "ib7", "makeWorkingKey", "[B", "encryptBlock", "decryptBlock" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesSerpentEngineBase = { "SerpentEngineBase", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x401, 29, 9, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesSerpentEngineBase;
}

@end

void OrgSpongycastleCryptoEnginesSerpentEngineBase_init(OrgSpongycastleCryptoEnginesSerpentEngineBase *self) {
  NSObject_init(self);
}

jint OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(jint x, jint bits) {
  OrgSpongycastleCryptoEnginesSerpentEngineBase_initialize();
  return (JreLShift32(x, bits)) | (JreURShift32(x, -bits));
}

jint OrgSpongycastleCryptoEnginesSerpentEngineBase_rotateRightWithInt_withInt_(jint x, jint bits) {
  OrgSpongycastleCryptoEnginesSerpentEngineBase_initialize();
  return (JreURShift32(x, bits)) | (JreLShift32(x, -bits));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesSerpentEngineBase)
