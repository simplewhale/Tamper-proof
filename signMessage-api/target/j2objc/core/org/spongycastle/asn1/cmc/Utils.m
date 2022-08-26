//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/Utils.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/cmc/BodyPartID.h"
#include "org/spongycastle/asn1/cmc/Utils.h"
#include "org/spongycastle/asn1/x509/Extension.h"

@implementation OrgSpongycastleAsn1CmcUtils

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1CmcUtils_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSObjectArray *)toBodyPartIDArrayWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)bodyPartIDs {
  return OrgSpongycastleAsn1CmcUtils_toBodyPartIDArrayWithOrgSpongycastleAsn1ASN1Sequence_(bodyPartIDs);
}

+ (IOSObjectArray *)cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray:(IOSObjectArray *)ids {
  return OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray_(ids);
}

+ (IOSObjectArray *)cloneWithOrgSpongycastleAsn1X509ExtensionArray:(IOSObjectArray *)ids {
  return OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1X509ExtensionArray_(ids);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmcBodyPartID;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmcBodyPartID;", 0x8, 2, 3, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X509Extension;", 0x8, 2, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(toBodyPartIDArrayWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray:);
  methods[3].selector = @selector(cloneWithOrgSpongycastleAsn1X509ExtensionArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "toBodyPartIDArray", "LOrgSpongycastleAsn1ASN1Sequence;", "clone", "[LOrgSpongycastleAsn1CmcBodyPartID;", "[LOrgSpongycastleAsn1X509Extension;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcUtils = { "Utils", "org.spongycastle.asn1.cmc", ptrTable, methods, NULL, 7, 0x0, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcUtils;
}

@end

void OrgSpongycastleAsn1CmcUtils_init(OrgSpongycastleAsn1CmcUtils *self) {
  NSObject_init(self);
}

OrgSpongycastleAsn1CmcUtils *new_OrgSpongycastleAsn1CmcUtils_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcUtils, init)
}

OrgSpongycastleAsn1CmcUtils *create_OrgSpongycastleAsn1CmcUtils_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcUtils, init)
}

IOSObjectArray *OrgSpongycastleAsn1CmcUtils_toBodyPartIDArrayWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *bodyPartIDs) {
  OrgSpongycastleAsn1CmcUtils_initialize();
  IOSObjectArray *ids = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(bodyPartIDs)) size] type:OrgSpongycastleAsn1CmcBodyPartID_class_()];
  for (jint i = 0; i != [bodyPartIDs size]; i++) {
    (void) IOSObjectArray_Set(ids, i, OrgSpongycastleAsn1CmcBodyPartID_getInstanceWithId_([bodyPartIDs getObjectAtWithInt:i]));
  }
  return ids;
}

IOSObjectArray *OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray_(IOSObjectArray *ids) {
  OrgSpongycastleAsn1CmcUtils_initialize();
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(ids))->size_ type:OrgSpongycastleAsn1CmcBodyPartID_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ids, 0, tmp, 0, ids->size_);
  return tmp;
}

IOSObjectArray *OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1X509ExtensionArray_(IOSObjectArray *ids) {
  OrgSpongycastleAsn1CmcUtils_initialize();
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(ids))->size_ type:OrgSpongycastleAsn1X509Extension_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ids, 0, tmp, 0, ids->size_);
  return tmp;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcUtils)
