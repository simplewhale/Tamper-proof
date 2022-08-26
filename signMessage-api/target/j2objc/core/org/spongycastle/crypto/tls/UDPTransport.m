//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/UDPTransport.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/net/DatagramPacket.h"
#include "java/net/DatagramSocket.h"
#include "org/spongycastle/crypto/tls/AlertDescription.h"
#include "org/spongycastle/crypto/tls/TlsFatalAlert.h"
#include "org/spongycastle/crypto/tls/UDPTransport.h"

@implementation OrgSpongycastleCryptoTlsUDPTransport

- (instancetype)initWithJavaNetDatagramSocket:(JavaNetDatagramSocket *)socket
                                      withInt:(jint)mtu {
  OrgSpongycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(self, socket, mtu);
  return self;
}

- (jint)getReceiveLimit {
  return receiveLimit_;
}

- (jint)getSendLimit {
  return sendLimit_;
}

- (jint)receiveWithByteArray:(IOSByteArray *)buf
                     withInt:(jint)off
                     withInt:(jint)len
                     withInt:(jint)waitMillis {
  [((JavaNetDatagramSocket *) nil_chk(socket_)) setSoTimeoutWithInt:waitMillis];
  JavaNetDatagramPacket *packet = new_JavaNetDatagramPacket_initWithByteArray_withInt_withInt_(buf, off, len);
  [socket_ receiveWithJavaNetDatagramPacket:packet];
  return [packet getLength];
}

- (void)sendWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)off
                  withInt:(jint)len {
  if (len > [self getSendLimit]) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
  }
  JavaNetDatagramPacket *packet = new_JavaNetDatagramPacket_initWithByteArray_withInt_withInt_(buf, off, len);
  [((JavaNetDatagramSocket *) nil_chk(socket_)) sendWithJavaNetDatagramPacket:packet];
}

- (void)close {
  [((JavaNetDatagramSocket *) nil_chk(socket_)) close];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaNetDatagramSocket:withInt:);
  methods[1].selector = @selector(getReceiveLimit);
  methods[2].selector = @selector(getSendLimit);
  methods[3].selector = @selector(receiveWithByteArray:withInt:withInt:withInt:);
  methods[4].selector = @selector(sendWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MIN_IP_OVERHEAD", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsUDPTransport_MIN_IP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "MAX_IP_OVERHEAD", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsUDPTransport_MAX_IP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "UDP_OVERHEAD", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsUDPTransport_UDP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "socket_", "LJavaNetDatagramSocket;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "receiveLimit_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "sendLimit_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaNetDatagramSocket;I", "LJavaIoIOException;", "receive", "[BIII", "send", "[BII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsUDPTransport = { "UDPTransport", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 6, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsUDPTransport;
}

@end

void OrgSpongycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(OrgSpongycastleCryptoTlsUDPTransport *self, JavaNetDatagramSocket *socket, jint mtu) {
  NSObject_init(self);
  if (![((JavaNetDatagramSocket *) nil_chk(socket)) isBound] || ![socket isConnected]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'socket' must be bound and connected");
  }
  self->socket_ = socket;
  self->receiveLimit_ = mtu - OrgSpongycastleCryptoTlsUDPTransport_MIN_IP_OVERHEAD - OrgSpongycastleCryptoTlsUDPTransport_UDP_OVERHEAD;
  self->sendLimit_ = mtu - OrgSpongycastleCryptoTlsUDPTransport_MAX_IP_OVERHEAD - OrgSpongycastleCryptoTlsUDPTransport_UDP_OVERHEAD;
}

OrgSpongycastleCryptoTlsUDPTransport *new_OrgSpongycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(JavaNetDatagramSocket *socket, jint mtu) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsUDPTransport, initWithJavaNetDatagramSocket_withInt_, socket, mtu)
}

OrgSpongycastleCryptoTlsUDPTransport *create_OrgSpongycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(JavaNetDatagramSocket *socket, jint mtu) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsUDPTransport, initWithJavaNetDatagramSocket_withInt_, socket, mtu)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsUDPTransport)
