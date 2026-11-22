/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "quic-stream-id-tag.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (QuicStreamIdTag);

QuicStreamIdTag::QuicStreamIdTag () : m_streamId (0) {}

QuicStreamIdTag::QuicStreamIdTag (uint64_t streamId) : m_streamId (streamId) {}

TypeId
QuicStreamIdTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicStreamIdTag")
    .SetParent<Tag> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicStreamIdTag> ()
  ;
  return tid;
}

TypeId
QuicStreamIdTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
QuicStreamIdTag::GetSerializedSize (void) const
{
  return 8;
}

void
QuicStreamIdTag::Serialize (TagBuffer i) const
{
  i.WriteU64 (m_streamId);
}

void
QuicStreamIdTag::Deserialize (TagBuffer i)
{
  m_streamId = i.ReadU64 ();
}

void
QuicStreamIdTag::Print (std::ostream &os) const
{
  os << "StreamId=" << m_streamId;
}

uint64_t
QuicStreamIdTag::GetStreamId (void) const
{
  return m_streamId;
}

void
QuicStreamIdTag::SetStreamId (uint64_t streamId)
{
  m_streamId = streamId;
}

} // namespace ns3
