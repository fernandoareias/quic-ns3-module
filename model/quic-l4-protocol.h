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

#ifndef QUICL4PROTOCOL_H
#define QUICL4PROTOCOL_H

#include <stdint.h>
#include <map>
#include "ns3/node.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"
#include "ns3/ip-l4-protocol.h"
#include "quic-header.h"
#include "quic-transport-parameters.h"
#include "ns3/socket.h"

namespace ns3 {

class QuicSocketBase;
class Ipv4EndPointDemux;
class Ipv6EndPointDemux;
class Ipv4EndPoint;
class Ipv6EndPoint;

/**
 * \ingroup quic
 *
 * \brief Container that encloses the Quic-Udp binding
 */
class QuicUdpBinding : public Object
{
public:
  QuicUdpBinding ();
  ~QuicUdpBinding ();

  static TypeId GetTypeId (void);

  Ptr<Socket> m_budpSocket;          //!< The UDP socket this binding is associated with
  Ptr<Socket> m_budpSocket6;         //!< The IPv6 UDP this binding is associated with
  Ptr<QuicSocketBase> m_quicSocket;  //!< The quic socket associated with this binding
  bool m_listenerBinding;            //!< A flag that indicates if in this binding resides the listening socket
  Address m_peerAddress;             //!< The peer address for this connection (used by cloned server sockets for SendTo)
  bool m_hasPeerAddress;             //!< Whether m_peerAddress is set
};

/**
 * \ingroup quic
 * \brief QUIC socket creation and multiplexing/demultiplexing
 *
 * This class is responsible for
 * - the creation of a QUIC socket
 * - the binding of the QUIC socket to a UDP socket
 *
 * The creation of QuicSocket are handled in the method CreateSocket, which is
 * called by QuicSocketFactory. Upon creation, this class is responsible to
 * the socket initialization and handle multiplexing/demultiplexing of data
 * between node's QUIC sockets. Demultiplexing is done by receiving
 * packets from UDP, and forwards them up to the right socket. Multiplexing
 * is done through the SendPacket function, which sends the packet down the stack.
 *
 * Moreover, this class SHOULD manage the connection authentication among the
 * peers by checking the packets it receives from the UDP layer going down
 * the stack.
 *
 * \see CreateSocket
 * \see NotifyNewAggregate
 * \see SendPacket
*/
class QuicL4Protocol : public IpL4Protocol
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);
  static const uint8_t PROT_NUMBER;

  QuicL4Protocol ();
  virtual ~QuicL4Protocol ();

  /**
   * \brief Set the node associated with this stack
   *
   * \param node the node to be associated with
   */
  void SetNode (Ptr<Node> node);

  /**
   * \brief Create a QUIC socket using the TypeId set by SocketType attribute
   *
   * \return A smart Socket pointer to a QuicSocket (e.g., QuicSocketBase)
   * allocated by this instance of the QUIC L4 protocol
   */
  Ptr<Socket> CreateSocket (void);

  /**
   * \brief Create a QUIC socket using the specified congestion control algorithm TypeId
   *
   * \return A smart Socket pointer to a QuicSocket (e.g., QuicSocketBase)
   * allocated by this instance of the QUIC L4 protocol
   *
   * \param congestionTypeId the congestion control algorithm TypeId
   */
  Ptr<Socket> CreateSocket (TypeId congestionTypeId);

  /**
   * \brief Create an UDP socket that will be used by QUIC
   *
   * \return a smart pointer to the UDP socket
   */
  Ptr<Socket> CreateUdpSocket (void);

  /**
   * \brief Create an IPv6 UDP socket that will be used by QUIC
   *
   * \return a smart pointer to the IPv6 UDP socket
   */
  Ptr<Socket> CreateUdpSocket6 (void);

  /**
   * \brief Bind the UDP socket (and create it if needed)
   *
   * \param socket the QuicSocketBase to be binded
   * \return the result of the bind call on the UDP socket
   */
  int UdpBind (Ptr<QuicSocketBase> socket);

  /**
   * \brief Bind the IPv6 UDP socket (and create it if needed)
   *
   * \param socket the QuicSocketBase to be binded
   * \return the result of the bind call on the IPv6 UDP socket
   */
  int UdpBind6 (Ptr<QuicSocketBase> socket);

  /**
   * \brief Bind the UDP socket (and create if needed) to a specific address
   *
   * \param address the address
   * \param socket the QuicSocketBase to be binded
   * \return the result of the bind call on the UDP socket
   */
  int UdpBind (const Address &address, Ptr<QuicSocketBase> socket);

  /**
   * \brief Connect the UDP socket
   *
   * \param address the address
   * \param socket the QuicSocketBase to be connected
   * \return the result of the connect call on the UDP socket
   */
  int UdpConnect (const Address & address, Ptr<QuicSocketBase> socket);

  /**
   * \brief Send a QUIC packet using the UDP socket
   *
   * \param udpSocket the UDP socket where the packet has to be sent
   * \param p the smart pointer to the packet
   * \param flags eventual flags for the UDP socket
   * \return the result of the send call on the UDP socket
   */
  int UdpSend (Ptr<Socket> udpSocket, Ptr<Packet> p, uint32_t flags) const;

  /**
   * \brief Receive a packet from the underlying UDP socket
   *
   * \param udpSocket the UDP socket where the packet has to be received
   * \param maxSize the smart pointer to the packet
   * \param flags eventual flags for the UDP socket
   * \param address the address
   * \return the received UDP packet
   */
  Ptr<Packet> UdpRecv (Ptr<Socket> udpSocket, uint32_t maxSize, uint32_t flags, Address &address);

  /**
   * \brief Get the max number of bytes an UDP Socket can send
   *
   * \param socket the QuicSocketBase to be checked
   * \return the max number of bytes an UDP Socket can send
   */
  uint32_t GetTxAvailable (Ptr<QuicSocketBase> socket) const;

  /**
   * \brief Get the max number of bytes an UDP Socket can read
   *
   * \param socket the QuicSocketBase to be checked
   * \return the max number of bytes an UDP Socket can read
   */
  uint32_t GetRxAvailable (Ptr<QuicSocketBase> socket) const;

  /**
   * \brief Get UDP socket address.
   *
   * \param quicSocket the QuicSocketBase to be checked
   * \param address the address name the UDP socket is associated with.
   * \returns 0 if success, -1 otherwise
   */
  int GetSockName (const ns3::QuicSocketBase* quicSocket, Address &address) const;

  /**
   * \brief Get the peer address of a connected UDP socket.
   *
   * \param quicSocket the QuicSocketBase to be checked
   * \param address the address the UDP socket is connected to.
   * \returns 0 if success, -1 otherwise
   */
  int GetPeerName (const ns3::QuicSocketBase* quicSocket, Address &address) const;

  /**
   * \brief Bind the UDP socket to specific device.
   *
   * \param socket the QuicSocketBase to be binded
   * \param netdevice Pointer to NetDevice of desired interface
   * \returns nothing
   */
  void BindToNetDevice (Ptr<QuicSocketBase> socket, Ptr<NetDevice> netdevice);

  /**
   * \brief Get the authenticated addresses vector
   *
   * \return The authenticated addresses vector for this L4 Protocol
   */
  const std::vector<Address >& GetAuthAddresses () const;

  /**
   * \brief Remember the transport parameters a server announced (RFC 9000 s7.4.1)
   *
   * A client that connects to the same server again with 0-RTT data uses them, as it has not yet heard from the
   * server and cannot open a stream without knowing its limits.
   *
   * \param server the address of the server
   * \param parameters the parameters the server announced
   */
  void RememberServerParameters (Ipv4Address server, const QuicTransportParameters &parameters);

  /**
   * \brief The transport parameters remembered for a server
   *
   * \param server the address of the server
   * \param parameters the parameters, when there are any
   * \return true if parameters were remembered for this server
   */
  bool GetRememberedParameters (Ipv4Address server, QuicTransportParameters &parameters) const;

  /**
   * \brief This method is called by the underlying UDP socket upon receiving a packet
   *
   * \param sock a smart pointer to the unerlying UDP socket
   */
  void ForwardUp (Ptr<Socket> sock);

  /**
   * \brief Set the receive callback for the underlyong UDP socket
   *
   * \param handler a callback
   * \param sock the socket
   */
  void SetRecvCallback (Callback<void, Ptr<Packet>, const QuicHeader&, Address&> handler, Ptr<Socket> sock);

  /**
   * \brief Called by the socket implementation to send a packet
   *
   * \param socket the QuicSocketBase that would send the packet
   * \param pck a smart pointer to a packet
   * \param outgoing the QuicHeader of the packet
   */
  void SendPacket (Ptr<QuicSocketBase> socket, Ptr<Packet> pkt, const QuicHeader &outgoing) const;

  /**
   * \brief Remove a socket (and its clones if it is a listener)
   *  If no sockets are left, close the UDP connection
   *
   * \param socket a smart pointer to the socket to be removed
   * \return a boolean which is false if the socket was not found and closed
   */
  bool RemoveSocket (Ptr<QuicSocketBase> socket);

  /**
   * \brief Set the listener QuicSocketBase
   *
   * \param sock a smart pointer to the socket to be set as listener
   * \return true if the settings succeeded, otherwhise false
   */
  bool SetListener (Ptr<QuicSocketBase> sock);

  /**
   * \\brief Derive the 128 bit stateless reset token of a connection id with this endpoint's secret
   * (msquic QuicLibraryGenerateStatelessResetToken)
   * \\param connectionId the connection id
   * \\param hi the upper 64 bits of the token
   * \\param lo the lower 64 bits of the token
   */
  void GenerateStatelessResetToken (uint64_t connectionId, uint64_t &hi, uint64_t &lo) const;

  /**
   * \\brief Pick a connection id not used by any connection of this endpoint
   * \\return the new id
   */
  uint64_t AllocateConnectionId (void);

  /**
   * \\brief Route packets that carry this connection id to a connection (msquic: the lookup table)
   * \\param connectionId the id
   * \\param socket the connection
   */
  void RegisterConnectionId (uint64_t connectionId, Ptr<QuicSocketBase> socket);

  /**
   * \\brief Stop routing a connection id
   * \\param connectionId the id
   */
  void UnregisterConnectionId (uint64_t connectionId);

  /**
   * \\brief Replace the local UDP socket of a client connection by one bound to a new local address
   * (msquic QUIC_PARAM_CONN_LOCAL_ADDRESS); the old socket is closed
   * \\param socket the connection
   * \\param newLocal the new local address (port 0 picks an ephemeral port)
   * \\return the new UDP socket, or null on failure
   */
  Ptr<Socket> RebindLocalAddress (Ptr<QuicSocketBase> socket, const Address &newLocal);

  /**
   * \\brief Make a UDP socket and peer address the path the connection sends on
   * \\param socket the connection
   * \\param udp the UDP socket
   * \\param remote the peer address
   */
  void SetPath (Ptr<QuicSocketBase> socket, Ptr<Socket> udp, const Address &remote);

  /**
   * \\brief The UDP socket and peer address the connection currently sends on
   * \\param socket the connection
   * \\param udp the UDP socket
   * \\param remote the peer address
   * \\return false if the connection has no binding
   */
  bool GetPath (Ptr<QuicSocketBase> socket, Ptr<Socket> &udp, Address &remote) const;

  /**
   * \\brief Send a packet on a given path, not necessarily the active one (probing)
   * \\param pkt the payload
   * \\param head the QUIC header
   * \\param udp the UDP socket
   * \\param remote the peer address
   */
  void SendPacketOnPath (Ptr<Packet> pkt, const QuicHeader &head, Ptr<Socket> udp, const Address &remote) const;

  /**
   * \brief Check if this L4 Protocol is Server
   *
   * \return true if this L4 Protocol is Server, otherwhise false
   */
  bool IsServer (void) const;

  /**
   * \brief Check if this L4 Protocol allows the 0-Rtt Handshake start
   *
   * \return true if this L4 Protocol allows the 0-Rtt Handshake start, otherwhise false
   */
  bool Is0RTTHandshakeAllowed () const;

  /**
   * \brief Allocate an IPv4 Endpoint
   * \return the Endpoint
   */
  Ipv4EndPoint * Allocate (void);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param address address to use
   * \return the Endpoint
   */
  Ipv4EndPoint * Allocate (Ipv4Address address);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param port port to use
   * \return the Endpoint
   */
  Ipv4EndPoint * Allocate (Ptr<NetDevice> boundNetDevice, uint16_t port);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param address address to use
   * \param port port to use
   * \return the Endpoint
   */
  Ipv4EndPoint * Allocate (Ptr<NetDevice> boundNetDevice, Ipv4Address address, uint16_t port);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param localAddress local address to use
   * \param localPort local port to use
   * \param peerAddress remote address to use
   * \param peerPort remote port to use
   * \return the Endpoint
   */
  Ipv4EndPoint * Allocate (Ptr<NetDevice> boundNetDevice,
                           Ipv4Address localAddress, uint16_t localPort,
                           Ipv4Address peerAddress, uint16_t peerPort);

  /**
   * \brief Allocate an IPv6 Endpoint
   * \return the Endpoint
   */
  Ipv6EndPoint * Allocate6 (void);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param address address to use
   * \return the Endpoint
   */
  Ipv6EndPoint * Allocate6 (Ipv6Address address);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param port port to use
   * \return the Endpoint
   */
  Ipv6EndPoint * Allocate6 (Ptr<NetDevice> boundNetDevice, uint16_t port);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param address address to use
   * \param port port to use
   * \return the Endpoint
   */
  Ipv6EndPoint * Allocate6 (Ptr<NetDevice> boundNetDevice, Ipv6Address address, uint16_t port);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param boundNetDevice Bound NetDevice (if any)
   * \param localAddress local address to use
   * \param localPort local port to use
   * \param peerAddress remote address to use
   * \param peerPort remote port to use
   * \return the Endpoint
   */
  Ipv6EndPoint * Allocate6 (Ptr<NetDevice> boundNetDevice,
                            Ipv6Address localAddress, uint16_t localPort,
                            Ipv6Address peerAddress, uint16_t peerPort);

  /**
   * \brief Remove an IPv4 Endpoint.
   * \param endPoint the end point to remove
   */
  void DeAllocate (Ipv4EndPoint *endPoint);
  /**
   * \brief Remove an IPv6 Endpoint.
   * \param endPoint the end point to remove
   */
  void DeAllocate (Ipv6EndPoint *endPoint);

  // Inherited from IpL4Protocol, not used in this implementation
  virtual enum IpL4Protocol::RxStatus Receive (Ptr<Packet> p,
                                               Ipv4Header const &incomingIpHeader,
                                               Ptr<Ipv4Interface> incomingInterface);
  virtual enum IpL4Protocol::RxStatus Receive (Ptr<Packet> p,
                                               Ipv6Header const &incomingIpHeader,
                                               Ptr<Ipv6Interface> incomingInterface);
  virtual void ReceiveIcmp (Ipv4Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv4Address payloadSource,Ipv4Address payloadDestination,
                            const uint8_t payload[8]);
  virtual void ReceiveIcmp (Ipv6Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv6Address payloadSource,Ipv6Address payloadDestination,
                            const uint8_t payload[8]);
  virtual void SetDownTarget (IpL4Protocol::DownTargetCallback cb);
  virtual void SetDownTarget6 (IpL4Protocol::DownTargetCallback6 cb);
  virtual int GetProtocolNumber (void) const;
  virtual IpL4Protocol::DownTargetCallback GetDownTarget (void) const;
  virtual IpL4Protocol::DownTargetCallback6 GetDownTarget6 (void) const;

protected:
  virtual void DoDispose (void);

  /**
   * \brief Setup socket factory and callbacks when aggregated to a node
   *
   * This function will notify other components connected to the node that a
   * new stack member is now connected.
   */
  virtual void NotifyNewAggregate ();

private:
  typedef std::vector< Ptr<QuicUdpBinding> > QuicUdpBindingList;  //!< container for the QuicUdp bindings

  /**
   * \brief Clone a QuicSocket and add it to the list of sockets associated to this protocol
   *
   * \param sock a smart pointer to the socket to be cloned
   * \return a smart pointer to the new cloned socket
   */
  Ptr<QuicSocketBase> CloneSocket (Ptr<QuicSocketBase> oldsock);

  /**
   * @brief Find the listening socket that owns the UDP socket a packet arrived on
   *
   * A node may host several listeners bound to different ports; the UDP
   * socket that received the packet identifies which one the peer targeted.
   *
   * @param udpSocket the UDP socket that received the packet
   * @return the matching listening socket, or the first listener if none matches
   */
  Ptr<QuicSocketBase> FindListener (Ptr<Socket> udpSocket) const;

  /**
   * \brief Check if an IPv4 address belongs to this node (loopback or local interface)
   *
   * \param addr the IPv4 address to check
   * \return true if the address is local to this node
   */
  bool IsLocalAddress (Ipv4Address addr) const;

  Ptr<Node> m_node;           //!< The node this stack is associated with
  TypeId m_rttTypeId;         //!< The type of RttEstimator objects
  TypeId m_congestionTypeId;  //!< The socket type of QUIC objects
  bool m_0RTTHandshakeStart;  //!< A flag indicating if the L4 Protocol allows the 0-RTT Hansdhake start
  std::map <Ptr<Socket>, Callback<void, Ptr<Packet>, const QuicHeader&, Address& > > m_socketHandlers;  //!< Callback handlers for sockets

  std::vector<Address > m_authAddresses;    //!< Authenticated addresses for this L4 Protocol
  std::map<Ipv4Address, QuicTransportParameters> m_rememberedParameters; //!< Parameters announced by servers this stack connected to
  std::map<uint64_t, Ptr<QuicSocketBase> > m_cidMap;  //!< Connection id -> connection (every id issued to a peer)
  uint64_t m_resetKeyA {0};                 //!< Secret of the stateless reset token function
  uint64_t m_resetKeyB {0};                 //!< Secret of the stateless reset token function

  /**
   * \\brief Answer a short header packet that matches no connection with a stateless reset (msquic binding.c)
   * \\param sock the UDP socket the packet arrived on
   * \\param from the sender
   * \\param header the received header
   * \\param packet the received payload
   */
  void SendStatelessReset (Ptr<Socket> sock, const Address &from, const QuicHeader &header, Ptr<Packet> packet);

  /**
   * \\brief Look for a stateless reset among the connections of this endpoint (msquic connection.c)
   * \\param packet the payload of a packet that matched no connection
   * \\return true if the packet reset a connection
   */
  bool ReceiveStatelessReset (Ptr<Packet> packet);
  QuicUdpBindingList m_quicUdpBindingList;  //!< List of QuicUdp bindings
  bool m_isServer;                          //!< A flag indicating if the L4 Protocol is server

  Ipv4EndPointDemux *m_endPoints;   //!< A list of IPv4 end points.
  Ipv6EndPointDemux *m_endPoints6;  //!< A list of IPv6 end points.

  // Inherited from IpL4Protocol, not used in this implementation
  IpL4Protocol::DownTargetCallback m_downTarget;
  IpL4Protocol::DownTargetCallback6 m_downTarget6;

};

} // namespace ns3

#endif /* QUIC_L4_PROTOCOL_H */
