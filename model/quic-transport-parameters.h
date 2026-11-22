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

#ifndef QUICTRANSPORTPARAMETERS_H
#define QUICTRANSPORTPARAMETERS_H

#include <stdint.h>
#include "ns3/header.h"
#include "ns3/buffer.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"

namespace ns3 {

/**
 * \ingroup quic
 * \brief Transport Parameters for the QUIC Protocol
 *
 * This class has fields corresponding to those in QUIC Transport Parameters
 * as well as methods for serialization to and deserialization from a buffer.
 *
 * Transport Parameters [Quic IETF Draft 13 Transport - sec. 6.6]
 * --------------------------------------------------------------
 *
 * During connection establishment, both endpoints make authenticated
 * declarations of their transport parameters. These declarations are
 * made unilaterally by each endpoint. Endpoints are required to comply
 * of with the restrictions implied by these parameters; the description
 * each parameter includes rules for its handling. QUIC encodes
 * transport parameters into a sequence of octets, which are then
 * included in the cryptographic handshake. Once the handshake
 * completes, the transport parameters declared by the peer are
 * available. Each endpoint validates the value provided by its peer.
 *
 */
class QuicTransportParameters : public Header
{
public:
  QuicTransportParameters ();
  virtual ~QuicTransportParameters ();

  // Inherited from Header
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /**
   * \brief Print Quic Transport Parameters into an output stream
   *
   * \param os output stream
   * \param tc Quic Transport Parameters to print
   * \return The ostream passed as first argument
   */
  friend std ::ostream& operator<< (std::ostream& os, QuicTransportParameters & tc);

  /**
   * Create the Transport Parameters block
   *
   * \param initial_max_stream_data the initial value for the maximum data that can be sent on any newly created stream
   * \param initial_max_data the initial value for the maximum amount of data that can be sent on the connection
   * \param initial_max_stream_id_bidi the the initial maximum number of application-owned bidirectional streams the peer may initiate
   * \param idleTimeout the max_idle_timeout value in milliseconds (0 disables it)
   * \param omit_connection the flag that indicates if the connection id is required in the upcoming connection
   * \param max_packet_size the limit on the size of packets that the endpoint is willing to receive
   * \param stateless_reset_token the stateless reset token
   * \param ack_delay_exponent the exponent used to decode the ack delay field in the ACK frame
   * \param initial_max_stream_id_uni the initial maximum number of application-owned unidirectional streams the peer may initiate
   * \return the generated QuicTransportParameters
   */
  static QuicTransportParameters CreateTransportParameters (uint32_t initial_max_stream_data, uint32_t initial_max_data, uint32_t initial_max_stream_id_bidi, uint32_t idleTimeout,
                                                            uint8_t omit_connection, uint16_t max_packet_size, /*uint128_t stateless_reset_token,*/ uint8_t ack_delay_exponent, uint32_t initial_max_stream_id_uni);

  // Getters, Setters and Controls

  /**
   * \brief Get the ack delay exponent
   * \return The ack delay exponent for this QuicTransportParameters
   */
  uint8_t GetAckDelayExponent () const;

  /**
   * \brief Set the ack delay exponent
   * \param ackDelayExponent the ack delay exponent for this QuicTransportParameters
   */
  void SetAckDelayExponent (uint8_t ackDelayExponent);

  /**
   * \brief Get the idle timeout
   * \return The idle timeout for this QuicTransportParameters
   */
  uint32_t GetIdleTimeout () const;

  /**
   * \brief Set the idle timeout
   * \param idleTimeout the idle timeout for this QuicTransportParameters
   */
  void SetIdleTimeout (uint32_t idleTimeout);

  /**
   * \brief Get the initial max data limit
   * \return The initial max data limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxData () const;

  /**
   * \brief Set the initial max data limit
   * \param initialMaxData the initial max data limit for this QuicTransportParameters
   */
  void SetInitialMaxData (uint32_t initialMaxData);

  /**
   * \brief Get the initial max stream data limit (bidi_local, 0x05)
   * \return The initial max stream data for locally-initiated bidi streams
   */
  uint32_t GetInitialMaxStreamData () const;

  /**
   * \brief Set the initial max stream data limit (bidi_local, 0x05)
   * \param initialMaxStreamData the initial max stream data for locally-initiated bidi streams
   */
  void SetInitialMaxStreamData (uint32_t initialMaxStreamData);

  /**
   * \brief Get initial_max_stream_data_bidi_remote (RFC 9000 §18.2, 0x06)
   * \return The initial max stream data for remotely-initiated bidi streams
   */
  uint32_t GetInitialMaxStreamDataBidiRemote () const;

  /**
   * \brief Set initial_max_stream_data_bidi_remote (RFC 9000 §18.2, 0x06)
   * \param val the initial max stream data for remotely-initiated bidi streams
   */
  void SetInitialMaxStreamDataBidiRemote (uint32_t val);

  /**
   * \brief Get initial_max_stream_data_uni (RFC 9000 §18.2, 0x07)
   * \return The initial max stream data for unidirectional streams
   */
  uint32_t GetInitialMaxStreamDataUni () const;

  /**
   * \brief Set initial_max_stream_data_uni (RFC 9000 §18.2, 0x07)
   * \param val the initial max stream data for unidirectional streams
   */
  void SetInitialMaxStreamDataUni (uint32_t val);

  /**
   * \brief Get max_ack_delay (RFC 9000 §18.2, 0x0b) in milliseconds
   * \return The max ack delay in ms (default 25)
   */
  uint16_t GetMaxAckDelay () const;

  /**
   * \brief Set max_ack_delay (RFC 9000 §18.2, 0x0b) in milliseconds
   * \param val the max ack delay in ms
   */
  void SetMaxAckDelay (uint16_t val);

  /**
   * \brief Get the min_ack_delay transport parameter (ack-frequency draft), in microseconds
   * \return the value; 0 means the peer does not support ACK_FREQUENCY
   */
  uint32_t GetMinAckDelay () const;

  /**
   * \brief Set the min_ack_delay transport parameter, in microseconds
   * \param val the value
   */
  void SetMinAckDelay (uint32_t val);

  /**
   * \brief Get the initial max bidirectional stream id limit
   * \return The initial max bidirectional stream id limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxStreamIdBidi () const;

  /**
   * \brief Set the initial max bidirectional stream id limit
   * \param initialMaxStreamIdBidi the initial max bidirectional stream id limit for this QuicTransportParameters
   */
  void SetInitialMaxStreamIdBidi (uint32_t initialMaxStreamIdBidi);

  /**
   * \brief Get the initial max unidirectional stream id limit
   * \return The initial max unidirectional stream id limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxStreamIdUni () const;

  /**
   * \brief Set the initial max unidirectional stream id limit
   * \param initialMaxStreamIdUni the initial max unidirectional stream id limit for this QuicTransportParameters
   */
  void SetInitialMaxStreamIdUni (uint32_t initialMaxStreamIdUni);

  /**
   * \brief Get the max packet size limit
   * \return The max packet size limit for this QuicTransportParameters
   */
  uint16_t GetMaxPacketSize () const;

  /**
   * \brief Set the max packet size limit
   * \param maxPacketSize the max packet size limit for this QuicTransportParameters
   */
  void SetMaxPacketSize (uint16_t maxPacketSize);

  /**
   * \brief Get the omit connection id flag
   * \return The omit connection id flag for this QuicTransportParameters
   */
  uint8_t GetOmitConnection () const;

  /**
   * \brief Set the omit connection id flag
   * \param omitConnection the omit connection id flag for this QuicTransportParameters
   */
  void SetOmitConnection (uint8_t omitConnection);

  /**
   * \brief Get the stateless reset token (RFC 9000 §18.2)
   */
  uint64_t GetStatelessResetTokenHi () const;
  uint64_t GetStatelessResetTokenLo () const;

  /**
   * \brief Set the stateless reset token (RFC 9000 §18.2)
   */
  void SetStatelessResetToken (uint64_t hi, uint64_t lo);

  /**
   * \brief Get the active connection id limit (RFC 9000 §18.2)
   * \return The active connection id limit (MUST be ≥2)
   */
  uint8_t GetActiveConnectionIdLimit () const;

  /**
   * \brief Set the active connection id limit (RFC 9000 §18.2)
   * \param limit the active connection id limit (MUST be ≥2)
   */
  void SetActiveConnectionIdLimit (uint8_t limit);

  /**
   * \brief Get the disable active migration flag (RFC 9000 §18.2)
   * \return true if active migration is disabled
   */
  uint8_t GetDisableActiveMigration () const;

  /**
   * \brief Set the disable active migration flag (RFC 9000 §18.2)
   * \param disable set to 1 to indicate migration is not supported
   */
  void SetDisableActiveMigration (uint8_t disable);

  /**
   * \brief Get initial_source_connection_id (RFC 9000 §18.2, 0x0f)
   */
  uint64_t GetInitialSourceConnectionId () const;

  /**
   * \brief Set initial_source_connection_id (RFC 9000 §18.2, 0x0f)
   */
  void SetInitialSourceConnectionId (uint64_t cid);

  /**
   * \brief Get original_destination_connection_id (RFC 9000 §18.2, 0x00)
   * Set by server to the DCID from the first Initial received from the client.
   */
  uint64_t GetOriginalDestinationConnectionId () const;

  /**
   * \brief Set original_destination_connection_id (RFC 9000 §18.2, 0x00)
   */
  void SetOriginalDestinationConnectionId (uint64_t cid);

  /**
   * Comparison operator
   * \param lhs left operand
   * \param rhs right operand
   * \return true if the operands are equal
   */
  friend bool operator== (const QuicTransportParameters &lhs, const QuicTransportParameters &rhs);

private:
  /**
   * \brief Calculates the Transpor Parameters block length (in words)
   *
   * Given the standard size of the Transport Parameters block, the method checks for options
   * and calculates the real length (in words).
   *
   * \return Transpor Parameters block length in 4-byte words
   */
  uint32_t CalculateHeaderLength () const;

  uint32_t m_initial_max_stream_data;             //!< initial_max_stream_data_bidi_local (0x05): max data on locally-initiated bidi streams
  uint32_t m_initial_max_data;            //!< The initial value for the maximum amount of data that can be sent on the connection
  uint32_t m_initial_max_stream_id_bidi;  //!< The the initial maximum number of application-owned bidirectional streams the peer may initiate
  uint32_t m_idleTimeout;                 //!< max_idle_timeout in milliseconds, 0 = disabled (RFC 9000 s18.2)
  uint8_t m_omit_connection;              //!< The flag that indicates if the connection id is required in the upcoming connection
  uint16_t m_max_packet_size;             //!< The limit on the size of packets that the endpoint is willing to receive
  uint64_t m_stateless_reset_token_hi;    //!< Upper 64 bits of the stateless reset token (RFC 9000 §18.2)
  uint64_t m_stateless_reset_token_lo;    //!< Lower 64 bits of the stateless reset token (RFC 9000 §18.2)
  uint8_t m_ack_delay_exponent;           //!< The exponent used to decode the ack delay field in the ACK frame
  uint32_t m_initial_max_stream_id_uni;   //!< The initial maximum number of application-owned unidirectional streams the peer may initiate
  uint32_t m_initial_max_stream_data_bidi_remote; //!< initial_max_stream_data_bidi_remote (RFC 9000 §18.2, 0x06)
  uint32_t m_initial_max_stream_data_uni;         //!< initial_max_stream_data_uni (RFC 9000 §18.2, 0x07)
  uint32_t m_min_ack_delay;                       //!< min_ack_delay in us (ack-frequency draft), 0 = unsupported
  uint16_t m_max_ack_delay;                       //!< max_ack_delay in ms (RFC 9000 §18.2, 0x0b), default 25
  uint8_t m_active_connection_id_limit;           //!< Active connection id limit ≥2 (RFC 9000 §18.2)
  uint8_t m_disable_active_migration;             //!< Disable active migration flag (RFC 9000 §18.2)
  uint64_t m_initial_source_connection_id;        //!< initial_source_connection_id (RFC 9000 §18.2, 0x0f)
  uint64_t m_original_destination_connection_id;  //!< original_destination_connection_id (RFC 9000 §18.2, 0x00)
};

} // namespace ns3

#endif /* QUIC_TRANSPORT_PARAMETERS_H_ */