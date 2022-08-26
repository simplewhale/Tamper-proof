//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSNodeUtil.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Math.h"
#include "java/lang/NullPointerException.h"
#include "org/spongycastle/pqc/crypto/xmss/HashTreeAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/KeyedHashFunctions.h"
#include "org/spongycastle/pqc/crypto/xmss/LTreeAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlus.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSNode.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSNodeUtil.h"

@implementation OrgSpongycastlePqcCryptoXmssXMSSNodeUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (OrgSpongycastlePqcCryptoXmssXMSSNode *)lTreeWithOrgSpongycastlePqcCryptoXmssWOTSPlus:(OrgSpongycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                            withOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters:(OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *)publicKey
                                           withOrgSpongycastlePqcCryptoXmssLTreeAddress:(OrgSpongycastlePqcCryptoXmssLTreeAddress *)address {
  return OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_lTreeWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_withOrgSpongycastlePqcCryptoXmssLTreeAddress_(wotsPlus, publicKey, address);
}

+ (OrgSpongycastlePqcCryptoXmssXMSSNode *)randomizeHashWithOrgSpongycastlePqcCryptoXmssWOTSPlus:(OrgSpongycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                                                       withOrgSpongycastlePqcCryptoXmssXMSSNode:(OrgSpongycastlePqcCryptoXmssXMSSNode *)left
                                                       withOrgSpongycastlePqcCryptoXmssXMSSNode:(OrgSpongycastlePqcCryptoXmssXMSSNode *)right
                                                    withOrgSpongycastlePqcCryptoXmssXMSSAddress:(OrgSpongycastlePqcCryptoXmssXMSSAddress *)address {
  return OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSAddress_(wotsPlus, left, right, address);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSNode;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSNode;", 0x8, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(lTreeWithOrgSpongycastlePqcCryptoXmssWOTSPlus:withOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters:withOrgSpongycastlePqcCryptoXmssLTreeAddress:);
  methods[2].selector = @selector(randomizeHashWithOrgSpongycastlePqcCryptoXmssWOTSPlus:withOrgSpongycastlePqcCryptoXmssXMSSNode:withOrgSpongycastlePqcCryptoXmssXMSSNode:withOrgSpongycastlePqcCryptoXmssXMSSAddress:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "lTree", "LOrgSpongycastlePqcCryptoXmssWOTSPlus;LOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters;LOrgSpongycastlePqcCryptoXmssLTreeAddress;", "randomizeHash", "LOrgSpongycastlePqcCryptoXmssWOTSPlus;LOrgSpongycastlePqcCryptoXmssXMSSNode;LOrgSpongycastlePqcCryptoXmssXMSSNode;LOrgSpongycastlePqcCryptoXmssXMSSAddress;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSNodeUtil = { "XMSSNodeUtil", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, NULL, 7, 0x0, 3, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSNodeUtil;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_init(OrgSpongycastlePqcCryptoXmssXMSSNodeUtil *self) {
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoXmssXMSSNodeUtil *new_OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSNodeUtil, init)
}

OrgSpongycastlePqcCryptoXmssXMSSNodeUtil *create_OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSNodeUtil, init)
}

OrgSpongycastlePqcCryptoXmssXMSSNode *OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_lTreeWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_withOrgSpongycastlePqcCryptoXmssLTreeAddress_(OrgSpongycastlePqcCryptoXmssWOTSPlus *wotsPlus, OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *publicKey, OrgSpongycastlePqcCryptoXmssLTreeAddress *address) {
  OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_initialize();
  if (publicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicKey == null");
  }
  if (address == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"address == null");
  }
  jint len = [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk([((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk(wotsPlus)) getParams])) getLen];
  IOSObjectArray *publicKeyBytes = [publicKey toByteArray];
  IOSObjectArray *publicKeyNodes = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(publicKeyBytes))->size_ type:OrgSpongycastlePqcCryptoXmssXMSSNode_class_()];
  for (jint i = 0; i < publicKeyBytes->size_; i++) {
    (void) IOSObjectArray_SetAndConsume(publicKeyNodes, i, new_OrgSpongycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(0, IOSObjectArray_Get(publicKeyBytes, i)));
  }
  address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[address getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:0])) withTreeIndexWithInt:[address getTreeIndex]])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
  while (len > 1) {
    for (jint i = 0; i < JreFpToInt(JavaLangMath_floorWithDouble_(len / 2)); i++) {
      address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssLTreeAddress *) nil_chk(address)) getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:[address getTreeHeight]])) withTreeIndexWithInt:i])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
      (void) IOSObjectArray_Set(publicKeyNodes, i, OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSAddress_(wotsPlus, IOSObjectArray_Get(publicKeyNodes, 2 * i), IOSObjectArray_Get(publicKeyNodes, (2 * i) + 1), address));
    }
    if (len % 2 == 1) {
      (void) IOSObjectArray_Set(publicKeyNodes, JreFpToInt(JavaLangMath_floorWithDouble_(len / 2)), IOSObjectArray_Get(publicKeyNodes, len - 1));
    }
    len = JreFpToInt(JavaLangMath_ceilWithDouble_((jdouble) len / 2));
    address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssLTreeAddress *) nil_chk(address)) getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:[address getTreeHeight] + 1])) withTreeIndexWithInt:[address getTreeIndex]])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
  }
  return IOSObjectArray_Get(publicKeyNodes, 0);
}

OrgSpongycastlePqcCryptoXmssXMSSNode *OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSNode_withOrgSpongycastlePqcCryptoXmssXMSSAddress_(OrgSpongycastlePqcCryptoXmssWOTSPlus *wotsPlus, OrgSpongycastlePqcCryptoXmssXMSSNode *left, OrgSpongycastlePqcCryptoXmssXMSSNode *right, OrgSpongycastlePqcCryptoXmssXMSSAddress *address) {
  OrgSpongycastlePqcCryptoXmssXMSSNodeUtil_initialize();
  if (left == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"left == null");
  }
  if (right == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"right == null");
  }
  if ([left getHeight] != [right getHeight]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"height of both nodes must be equal");
  }
  if (address == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"address == null");
  }
  IOSByteArray *publicSeed = [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk(wotsPlus)) getPublicSeed];
  if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssLTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssLTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:0])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssHashTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:0])) build], [OrgSpongycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *key = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssLTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssLTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:1])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssHashTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:1])) build], [OrgSpongycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *bitmask0 = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssLTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssLTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssLTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:2])) build], [OrgSpongycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[OrgSpongycastlePqcCryptoXmssHashTreeAddress class]]) {
    OrgSpongycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (OrgSpongycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:2])) build], [OrgSpongycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *bitmask1 = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  jint n = [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk([wotsPlus getParams])) getDigestSize];
  IOSByteArray *tmpMask = [IOSByteArray newArrayWithLength:2 * n];
  for (jint i = 0; i < n; i++) {
    *IOSByteArray_GetRef(tmpMask, i) = (jbyte) (IOSByteArray_Get(nil_chk([left getValue]), i) ^ IOSByteArray_Get(nil_chk(bitmask0), i));
  }
  for (jint i = 0; i < n; i++) {
    *IOSByteArray_GetRef(tmpMask, i + n) = (jbyte) (IOSByteArray_Get(nil_chk([right getValue]), i) ^ IOSByteArray_Get(nil_chk(bitmask1), i));
  }
  IOSByteArray *out = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) HWithByteArray:key withByteArray:tmpMask];
  return new_OrgSpongycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_([left getHeight], out);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSNodeUtil)
