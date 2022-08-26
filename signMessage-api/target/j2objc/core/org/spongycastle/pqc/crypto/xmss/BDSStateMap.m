//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/BDSStateMap.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Integer.h"
#include "java/util/Iterator.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "java/util/TreeMap.h"
#include "org/spongycastle/pqc/crypto/xmss/BDS.h"
#include "org/spongycastle/pqc/crypto/xmss/BDSStateMap.h"
#include "org/spongycastle/pqc/crypto/xmss/OTSHashAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSUtil.h"
#include "org/spongycastle/util/Integers.h"

@interface OrgSpongycastlePqcCryptoXmssBDSStateMap () {
 @public
  id<JavaUtilMap> bdsState_;
}

- (void)updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                                           withLong:(jlong)globalIndex
                                                      withByteArray:(IOSByteArray *)publicSeed
                                                      withByteArray:(IOSByteArray *)secretKeySeed;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssBDSStateMap, bdsState_, id<JavaUtilMap>)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssBDSStateMap_updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed);

@implementation OrgSpongycastlePqcCryptoXmssBDSStateMap

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoXmssBDSStateMap_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                                            withLong:(jlong)globalIndex
                                                       withByteArray:(IOSByteArray *)publicSeed
                                                       withByteArray:(IOSByteArray *)secretKeySeed {
  OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
  return self;
}

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssBDSStateMap:(OrgSpongycastlePqcCryptoXmssBDSStateMap *)stateMap
               withOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                                       withLong:(jlong)globalIndex
                                                  withByteArray:(IOSByteArray *)publicSeed
                                                  withByteArray:(IOSByteArray *)secretKeySeed {
  OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, stateMap, params, globalIndex, publicSeed, secretKeySeed);
  return self;
}

- (void)updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                                           withLong:(jlong)globalIndex
                                                      withByteArray:(IOSByteArray *)publicSeed
                                                      withByteArray:(IOSByteArray *)secretKeySeed {
  OrgSpongycastlePqcCryptoXmssBDSStateMap_updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
}

- (void)setXMSSWithOrgSpongycastlePqcCryptoXmssXMSSParameters:(OrgSpongycastlePqcCryptoXmssXMSSParameters *)xmss {
  for (id<JavaUtilIterator> it = [((id<JavaUtilSet>) nil_chk([((id<JavaUtilMap>) nil_chk(bdsState_)) keySet])) iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    JavaLangInteger *key = (JavaLangInteger *) cast_chk([it next], [JavaLangInteger class]);
    OrgSpongycastlePqcCryptoXmssBDS *bds = [bdsState_ getWithId:key];
    [((OrgSpongycastlePqcCryptoXmssBDS *) nil_chk(bds)) setXMSSWithOrgSpongycastlePqcCryptoXmssXMSSParameters:xmss];
    [bds validate];
  }
}

- (jboolean)isEmpty {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) isEmpty];
}

- (OrgSpongycastlePqcCryptoXmssBDS *)getWithInt:(jint)index {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) getWithId:OrgSpongycastleUtilIntegers_valueOfWithInt_(index)];
}

- (OrgSpongycastlePqcCryptoXmssBDS *)updateWithInt:(jint)index
                                     withByteArray:(IOSByteArray *)publicSeed
                                     withByteArray:(IOSByteArray *)secretKeySeed
    withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) putWithId:OrgSpongycastleUtilIntegers_valueOfWithInt_(index) withId:[((OrgSpongycastlePqcCryptoXmssBDS *) nil_chk([bdsState_ getWithId:OrgSpongycastleUtilIntegers_valueOfWithInt_(index)])) getNextStateWithByteArray:publicSeed withByteArray:secretKeySeed withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress]];
}

- (void)putWithInt:(jint)index
withOrgSpongycastlePqcCryptoXmssBDS:(OrgSpongycastlePqcCryptoXmssBDS *)bds {
  (void) [((id<JavaUtilMap>) nil_chk(bdsState_)) putWithId:OrgSpongycastleUtilIntegers_valueOfWithInt_(index) withId:bds];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssBDS;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssBDS;", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[2].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssBDSStateMap:withOrgSpongycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[3].selector = @selector(updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[4].selector = @selector(setXMSSWithOrgSpongycastlePqcCryptoXmssXMSSParameters:);
  methods[5].selector = @selector(isEmpty);
  methods[6].selector = @selector(getWithInt:);
  methods[7].selector = @selector(updateWithInt:withByteArray:withByteArray:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[8].selector = @selector(putWithInt:withOrgSpongycastlePqcCryptoXmssBDS:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bdsState_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x12, -1, -1, 11, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssXMSSMTParameters;J[B[B", "LOrgSpongycastlePqcCryptoXmssBDSStateMap;LOrgSpongycastlePqcCryptoXmssXMSSMTParameters;J[B[B", "updateState", "setXMSS", "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", "get", "I", "update", "I[B[BLOrgSpongycastlePqcCryptoXmssOTSHashAddress;", "put", "ILOrgSpongycastlePqcCryptoXmssBDS;", "Ljava/util/Map<Ljava/lang/Integer;Lorg/spongycastle/pqc/crypto/xmss/BDS;>;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssBDSStateMap = { "BDSStateMap", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x1, 9, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssBDSStateMap;
}

@end

void OrgSpongycastlePqcCryptoXmssBDSStateMap_init(OrgSpongycastlePqcCryptoXmssBDSStateMap *self) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *new_OrgSpongycastlePqcCryptoXmssBDSStateMap_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, init)
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *create_OrgSpongycastlePqcCryptoXmssBDSStateMap_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, init)
}

void OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
  for (jlong index = 0; index < globalIndex; index++) {
    OrgSpongycastlePqcCryptoXmssBDSStateMap_updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, index, publicSeed, secretKeySeed);
  }
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *new_OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, params, globalIndex, publicSeed, secretKeySeed)
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *create_OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, params, globalIndex, publicSeed, secretKeySeed)
}

void OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *self, OrgSpongycastlePqcCryptoXmssBDSStateMap *stateMap, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
  for (id<JavaUtilIterator> it = [((id<JavaUtilSet>) nil_chk([((OrgSpongycastlePqcCryptoXmssBDSStateMap *) nil_chk(stateMap))->bdsState_ keySet])) iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    JavaLangInteger *key = (JavaLangInteger *) cast_chk([it next], [JavaLangInteger class]);
    (void) [self->bdsState_ putWithId:key withId:[stateMap->bdsState_ getWithId:key]];
  }
  OrgSpongycastlePqcCryptoXmssBDSStateMap_updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *new_OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *stateMap, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, stateMap, params, globalIndex, publicSeed, secretKeySeed)
}

OrgSpongycastlePqcCryptoXmssBDSStateMap *create_OrgSpongycastlePqcCryptoXmssBDSStateMap_initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *stateMap, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssBDSStateMap, initWithOrgSpongycastlePqcCryptoXmssBDSStateMap_withOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, stateMap, params, globalIndex, publicSeed, secretKeySeed)
}

void OrgSpongycastlePqcCryptoXmssBDSStateMap_updateStateWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(OrgSpongycastlePqcCryptoXmssBDSStateMap *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  OrgSpongycastlePqcCryptoXmssXMSSParameters *xmssParams = [((OrgSpongycastlePqcCryptoXmssXMSSMTParameters *) nil_chk(params)) getXMSSParameters];
  jint xmssHeight = [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(xmssParams)) getHeight];
  jlong indexTree = OrgSpongycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(globalIndex, xmssHeight);
  jint indexLeaf = OrgSpongycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(globalIndex, xmssHeight);
  OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withTreeAddressWithLong:indexTree])) withOTSAddressWithInt:indexLeaf])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  if (indexLeaf < ((JreLShift32(1, xmssHeight)) - 1)) {
    if ([self getWithInt:0] == nil || indexLeaf == 0) {
      [self putWithInt:0 withOrgSpongycastlePqcCryptoXmssBDS:new_OrgSpongycastlePqcCryptoXmssBDS_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_withByteArray_withByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(xmssParams, publicSeed, secretKeySeed, otsHashAddress)];
    }
    (void) [self updateWithInt:0 withByteArray:publicSeed withByteArray:secretKeySeed withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress];
  }
  for (jint layer = 1; layer < [params getLayers]; layer++) {
    indexLeaf = OrgSpongycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(indexTree, xmssHeight);
    indexTree = OrgSpongycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(indexTree, xmssHeight);
    otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:layer])) withTreeAddressWithLong:indexTree])) withOTSAddressWithInt:indexLeaf])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
    if (indexLeaf < ((JreLShift32(1, xmssHeight)) - 1) && OrgSpongycastlePqcCryptoXmssXMSSUtil_isNewAuthenticationPathNeededWithLong_withInt_withInt_(globalIndex, xmssHeight, layer)) {
      if ([self getWithInt:layer] == nil) {
        [self putWithInt:layer withOrgSpongycastlePqcCryptoXmssBDS:new_OrgSpongycastlePqcCryptoXmssBDS_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_withByteArray_withByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_([params getXMSSParameters], publicSeed, secretKeySeed, otsHashAddress)];
      }
      (void) [self updateWithInt:layer withByteArray:publicSeed withByteArray:secretKeySeed withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress];
    }
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssBDSStateMap)