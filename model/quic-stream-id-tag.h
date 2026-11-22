/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef QUIC_STREAM_ID_TAG_H
#define QUIC_STREAM_ID_TAG_H

#include "ns3/tag.h"

namespace ns3 {

/**
 * \ingroup quic
 * \brief Byte tag attached by the QUIC stack to the payload delivered to the
 * application, identifying the stream that carried each byte range.
 * Applications can read it with Packet::EnumerateByteTags / ByteTagIterator.
 */
class QuicStreamIdTag : public Tag
{
public:
  QuicStreamIdTag ();
  QuicStreamIdTag (uint64_t streamId);

  static TypeId GetTypeId (void);
  TypeId GetInstanceTypeId (void) const override;
  uint32_t GetSerializedSize (void) const override;
  void Serialize (TagBuffer i) const override;
  void Deserialize (TagBuffer i) override;
  void Print (std::ostream &os) const override;

  uint64_t GetStreamId (void) const;
  void SetStreamId (uint64_t streamId);

private:
  uint64_t m_streamId; //!< stream that delivered the tagged bytes
};

} // namespace ns3

#endif /* QUIC_STREAM_ID_TAG_H */
