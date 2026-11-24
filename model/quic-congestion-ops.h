/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#ifndef QUICCONGESTIONOPS_H
#define QUICCONGESTIONOPS_H

#include "ns3/timer.h"
#include "ns3/object.h"
#include "quic-subheader.h"
#include "ns3/tcp-congestion-ops.h"
#include "ns3/tcp-socket-base.h"
#include "quic-socket-base.h"
#include "quic-socket-tx-buffer.h"

namespace ns3 {

/**
 * \ingroup quic
 * \defgroup congestionOps Congestion Control Algorithms.
 *
 * The various congestion control algorithms.
 */

/**
 * \ingroup congestionOps
 *
 * \brief Congestion control abstract class
 *
 * The congestion control is splitted from the main socket code, and it is a
 * pluggable component. An interface has been defined; variables are maintained
 * in the QuicSocketState class, while subclasses of QuicCongestionOps operate
 * over an instance of that class.
 *
 * The design extends TcpNewReno to provide compatibility with the TCP congestion
 * control implementations, as well as the possibility of extending it with new
 * QUIC-related capabilities.
 *
 */
class QuicCongestionOps : public TcpNewReno
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QuicCongestionOps ();
  QuicCongestionOps (const QuicCongestionOps& sock);
  ~QuicCongestionOps ();

  /**
   * \brief Get the name of the congestion control algorithm
   *
   * \return A string identifying the name
   */
  std::string GetName () const;

  /**
   * \brief Whether the sender has to space its packets by the pacing rate this algorithm sets
   *
   * The default is no: the socket then paces by its window and its round trip time, as msquic does. BBR sets a pacing
   * rate that is part of its model (the gains of its states are gains of that rate), so it asks for it.
   *
   * \return true if the pacing rate of the TCB is the rate to send at
   */
  virtual bool UsesPacingRate () const;

  /**
   * \brief Copy the congestion control algorithm across socket
   *
   * \return a pointer of the copied object
   */
  Ptr<TcpCongestionOps> Fork ();

  // QuicCongestionControl Draft10

  /**
   * \brief Method called when a packet is sent. It updates the quantities in the tcb
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param packetNumber the packet number
   * \param isAckOnly a flag to signal if the packet has only an ACK frame
   */
  virtual void OnPacketSent (Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber, bool isAckOnly);

  /**
   * \brief Method called when an ack is received. It process the received ack and updates
   *   the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param ack the received ACK
   * \param newAcks the newly acked packets
   * \param rs the connection RateSample
   */
  virtual void OnAckReceived (Ptr<TcpSocketState> tcb, QuicSubheader &ack, std::vector<Ptr<QuicSocketTxItem> > newAcks,
                              const struct RateSample *rs);

  /**
   * \brief Method called when a packet is lost. It process the lost packets and updates
   *   the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param lostPackets the lost packets
   */
  virtual void OnPacketsLost (Ptr<TcpSocketState> tcb, std::vector<Ptr<QuicSocketTxItem> > lostPackets);

  /**
   * \brief Check if in recovery period
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param packetNumber to be checked
   * \return true if in recovery, false otherwhise
   */
  bool InRecovery (Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber);

public:
  /**
   * \brief A packet previously declared lost was acknowledged (spurious loss)
   * \param tcb the socket state
   * \param packetNumber number of the packet that had been declared lost
   */
  virtual void OnSpuriousLoss (Ptr<TcpSocketState> tcb, SequenceNumber32 packetNumber);

  /**
   * \\brief The connection moved to another network path: forget what was learned about the old one
   * (msquic QuicCongestionControlReset on a path change that is not a UDP port rebind)
   * \\param tcb the socket state
   */
  virtual void OnPathChange (Ptr<TcpSocketState> tcb);

protected:
  /**
   * \brief Reduce the window on a new congestion event (new recovery epoch)
   * \param tcbd the socket state
   */
  virtual void OnCongestionEvent (Ptr<QuicSocketState> tcbd);

  /**
   * \brief Collapse the window on persistent congestion (RFC 9002 s7.6)
   * \param tcbd the socket state
   */
  virtual void OnPersistentCongestion (Ptr<QuicSocketState> tcbd);

  // QuicCongestionControl Draft10

  /**
   * \brief Method called to update the Rtt. It updates the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param latestRtt the latest Rtt
   * \param ackDelay the ack delay
   */
  void UpdateRtt (Ptr<TcpSocketState> tcb, Time latestRtt, Time ackDelay);

  /**
   * \brief Method called when a packet is acked. It process the acked packet and updates
   *   the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param ackedPacked the acked packet
   */
  virtual void OnPacketAcked (Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket);

  /**
   * \brief Method called when a packet is acked. It updates the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   * \param ackedPacked the acked packet
   */
  void OnPacketAckedCC (Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket);

  /**
   * \brief Method called when retransmission timeout fires. It updates the quantities in the tcb.
   *
   * \param tcb a smart pointer to the SocketState (it accepts a QuicSocketState)
   */
  virtual void OnRetransmissionTimeoutVerified (Ptr<TcpSocketState> tcb);

};

}
#endif //QUIC_NS3_QUIC_CONGESTION_OPS_H_H
