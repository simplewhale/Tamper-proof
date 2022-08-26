//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/LTreeAddress.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/pqc/crypto/xmss/LTreeAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSAddress.h"
#include "org/spongycastle/util/Pack.h"

#pragma clang diagnostic ignored "-Wincomplete-implementation"

@interface OrgSpongycastlePqcCryptoXmssLTreeAddress () {
 @public
  jint lTreeAddress_;
  jint treeHeight_;
  jint treeIndex_;
}

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder:(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)builder;

@end

inline jint OrgSpongycastlePqcCryptoXmssLTreeAddress_get_TYPE(void);
#define OrgSpongycastlePqcCryptoXmssLTreeAddress_TYPE 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastlePqcCryptoXmssLTreeAddress, TYPE, jint)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress *self, OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder);

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssLTreeAddress *new_OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssLTreeAddress *create_OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder);

@interface OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder () {
 @public
  jint lTreeAddress_;
  jint treeHeight_;
  jint treeIndex_;
}

@end

@implementation OrgSpongycastlePqcCryptoXmssLTreeAddress

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder:(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)builder {
  OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(self, builder);
  return self;
}

- (IOSByteArray *)toByteArray {
  IOSByteArray *byteRepresentation = [super toByteArray];
  OrgSpongycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(lTreeAddress_, byteRepresentation, 16);
  OrgSpongycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(treeHeight_, byteRepresentation, 20);
  OrgSpongycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(treeIndex_, byteRepresentation, 24);
  return byteRepresentation;
}

- (jint)getLTreeAddress {
  return lTreeAddress_;
}

- (jint)getTreeHeight {
  return treeHeight_;
}

- (jint)getTreeIndex {
  return treeIndex_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder:);
  methods[1].selector = @selector(toByteArray);
  methods[2].selector = @selector(getLTreeAddress);
  methods[3].selector = @selector(getTreeHeight);
  methods[4].selector = @selector(getTreeIndex);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TYPE", "I", .constantValue.asInt = OrgSpongycastlePqcCryptoXmssLTreeAddress_TYPE, 0x1a, -1, -1, -1, -1 },
    { "lTreeAddress_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "treeHeight_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "treeIndex_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssLTreeAddress = { "LTreeAddress", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 5, 4, -1, 0, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssLTreeAddress;
}

@end

void OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress *self, OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder) {
  OrgSpongycastlePqcCryptoXmssXMSSAddress_initWithOrgSpongycastlePqcCryptoXmssXMSSAddress_Builder_(self, builder);
  self->lTreeAddress_ = ((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk(builder))->lTreeAddress_;
  self->treeHeight_ = builder->treeHeight_;
  self->treeIndex_ = builder->treeIndex_;
}

OrgSpongycastlePqcCryptoXmssLTreeAddress *new_OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssLTreeAddress, initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_, builder)
}

OrgSpongycastlePqcCryptoXmssLTreeAddress *create_OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *builder) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssLTreeAddress, initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssLTreeAddress)

@implementation OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)withLTreeAddressWithInt:(jint)val {
  lTreeAddress_ = val;
  return self;
}

- (OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)withTreeHeightWithInt:(jint)val {
  treeHeight_ = val;
  return self;
}

- (OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)withTreeIndexWithInt:(jint)val {
  treeIndex_ = val;
  return self;
}

- (OrgSpongycastlePqcCryptoXmssXMSSAddress *)build {
  return new_OrgSpongycastlePqcCryptoXmssLTreeAddress_initWithOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_(self);
}

- (OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *)getThis {
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;", 0x4, 2, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;", 0x4, 3, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSAddress;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(withLTreeAddressWithInt:);
  methods[2].selector = @selector(withTreeHeightWithInt:);
  methods[3].selector = @selector(withTreeIndexWithInt:);
  methods[4].selector = @selector(build);
  methods[5].selector = @selector(getThis);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "lTreeAddress_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "treeHeight_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "treeIndex_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withLTreeAddress", "I", "withTreeHeight", "withTreeIndex", "LOrgSpongycastlePqcCryptoXmssLTreeAddress;", "Lorg/spongycastle/pqc/crypto/xmss/XMSSAddress$Builder<Lorg/spongycastle/pqc/crypto/xmss/LTreeAddress$Builder;>;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder = { "Builder", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0xc, 6, 3, 4, -1, -1, 5, -1 };
  return &_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder;
}

@end

void OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *self) {
  OrgSpongycastlePqcCryptoXmssXMSSAddress_Builder_initWithInt_(self, OrgSpongycastlePqcCryptoXmssLTreeAddress_TYPE);
  self->lTreeAddress_ = 0;
  self->treeHeight_ = 0;
  self->treeIndex_ = 0;
}

OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder, init)
}

OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *create_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder)
