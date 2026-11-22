/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 */

#define __STDC_LIMIT_MACROS

#include "ns3/object.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/nstime.h"
#include "quic-socket.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocket");

NS_OBJECT_ENSURE_REGISTERED (QuicSocket);

const char* const
QuicSocket::QuicStateName[QuicSocket::LAST_STATE] = {
  "IDLE", "LISTENING", "CONNECTING_SVR",
  "CONNECTING_CLT", "OPEN", "CLOSING"
};

TypeId
QuicSocket::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocket")
    .SetParent<Socket> ()
    .SetGroupName ("Internet")
  ;
  return tid;
}

QuicSocket::QuicSocket ()
  : Socket (),
  m_socketType (NONE)
{
  NS_LOG_FUNCTION_NOARGS ();
}

QuicSocket::QuicSocket (const QuicSocket& sock)
  : Socket (sock),
  m_socketType (sock.m_socketType)
{
  NS_LOG_FUNCTION_NOARGS ();
}

QuicSocket::~QuicSocket ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

QuicSocket::QuicSocketTypes_t
QuicSocket::GetQuicSocketType () const
{
  return m_socketType;
}

void
QuicSocket::SetQuicSocketType (QuicSocketTypes_t m_socketType)
{
  QuicSocket::m_socketType = m_socketType;
}

bool
QuicSocket::CheckVersionNegotiation (uint32_t version)
{
  // RFC 9000 s15: version 0 and the reserved versions 0x?a?a?a?a are for negotiation
  return  (version == QUIC_VERSION_NEGOTIATION) || ((version & 0x0F0F0F0F) == QUIC_VERSION_NEGOTIATION_PATTERN);
}

} // namespace ns3
