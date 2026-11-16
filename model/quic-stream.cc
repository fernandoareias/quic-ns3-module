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
#include "quic-stream.h"
#include "ns3/node.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicStream");

NS_OBJECT_ENSURE_REGISTERED (QuicStream);

const char* const
QuicStream::QuicStreamStateName[QuicStream::LAST_STATE] = {"IDLE", "OPEN", "SEND", "RECV", "SIZE_KNOWN", "DATA_SENT", "DATA_RECVD", "DATA_READ", "RESET_SENT", "RESET_RECVD", "RESET_READ"};

TypeId
QuicStream::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicStream")
    .SetParent<Object> ()
    .SetGroupName ("Internet")
  ;
  return tid;
}

QuicStream::QuicStream ()
  : Object ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

QuicStream::~QuicStream ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

} // namespace ns3
