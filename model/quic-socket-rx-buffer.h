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

#ifndef QUICSOCKETRXBUFFER_H
#define QUICSOCKETRXBUFFER_H

#include <map>
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/sequence-number.h"
#include "ns3/ptr.h"
#include "quic-header.h"
#include "quic-subheader.h"
#include "quic-l5-protocol.h"
#include "ns3/object.h"

namespace ns3 {

/**
 * \ingroup quic
 *
 * \brief Item that encloses the received Quic Stream frame
 */
class QuicSocketRxItem
{
public:
  QuicSocketRxItem ();
  QuicSocketRxItem (const QuicSocketRxItem &other);

  /**
   * \brief Print the Item
   * \param os ostream
   */
  void Print (std::ostream &os) const;

  /**
   * Comparison operator
   * \param other rhs operand
   * \return true if the rhs operand offset is greater than the lhs one
   */
  bool operator< (const QuicSocketRxItem& other)
  {
    return m_offset < other.m_offset;
  }

  /**
   * Equal operator
   * \param other rhs operand
   * \return true if the operands are equal
   */
  bool operator== (const QuicSocketRxItem& other)
  {
    return (this->m_offset == other.m_offset) and (this->m_fin == other.m_fin) and (this->m_packet == other.m_packet);
  }

  Ptr<Packet> m_packet;  //!< Stream Frame
  uint64_t m_offset;     //!< Offset of the Stream Frame
  bool m_fin;            //!< FIN bit of the Stream Frame
};

/**
 * \ingroup quic
 *
 * \brief Rx socket buffer for QUIC
 */
class QuicSocketRxBuffer : public Object
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QuicSocketRxBuffer ();
  virtual ~QuicSocketRxBuffer ();

  /**
   * Print the buffer information to a string,
   * including the list of received packets
   *
   * \param os the std::ostream object
   */
  void Print (std::ostream & os) const;

  /**
   * Get the buffer occupancy in bytes
   *
   * \return the buffer occupancy in bytes
   */
  uint32_t Size (void) const;

  /**
   * Get the maximum buffer size
   *
   * \return the buffer size
   */
  uint32_t GetMaxBufferSize (void) const;

  /**
   * Set the maximum buffer size
   *
   * \param s the new buffer size
   */
  void SetMaxBufferSize (uint32_t s);

  /**
   * Return the available space in the buffer
   *
   * \return the available buffer memory
   */
  uint32_t Available () const;

  /**
   * Add a packet in the buffer
   *
   * \param p a pointer to the packet
   * \param force store the packet even when it does not fit: data that was already acknowledged and counted
   *        by flow control must not be dropped
   * \return true if the insertion was successful
   */
  bool Add (Ptr<Packet> p, bool force = false);

  /**
   * Try to extract maxSize bytes from the buffer
   *
   * \param maxSize the number of bytes to extract
   * \return a smart pointer to the packet; a pointer to 0 if there is no data to extract
   * (or the first packet in the buffer is larger than maxSize)
   */
  Ptr<Packet> Extract (uint32_t maxSize);

private:
  typedef std::vector<QuicSocketRxItem*> QuicStreamRxPacketList;  //!< Container for data stored in the buffer
  typedef std::vector<Ptr<Packet> > QuicSocketRxPacketList;       //!< Container for data stored in the buffer

  QuicSocketRxPacketList m_socketRecvList;  //!< List of received packets with additional info
  uint32_t m_recvSize;                      //!< Current buffer occupancy
  uint32_t m_recvSizeTot;                   //!< Total number of bytes received
  uint32_t m_maxBuffer;                     //!< Maximum buffer size

};

} //namepsace ns3

#endif /* QUIC_SOCKET_RX_BUFFER_H */
