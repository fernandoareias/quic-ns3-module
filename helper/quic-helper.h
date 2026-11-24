/*
 * Copyright (c) 2008 INRIA
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#ifndef QUIC_HELPER_H
#define QUIC_HELPER_H

#include "ns3/internet-stack-helper.h"
#include "ns3/node-container.h"
#include "ns3/ptr.h"

namespace ns3
{

/**
 * \ingroup quic
 *
 * \brief Helper to install the QUIC stack on a set of nodes.
 *
 * Extends InternetStackHelper by additionally aggregating ns3::QuicL4Protocol
 * to each node, enabling QUIC socket creation via the standard Socket API.
 *
 * Usage:
 * \code
 *   NodeContainer nodes;
 *   nodes.Create(2);
 *   QuicHelper quic;
 *   quic.InstallQuic(nodes);
 * \endcode
 */
class QuicHelper : public InternetStackHelper
{
  public:
    /**
     * For each node in the input container, aggregate implementations of the
     * ns3::Ipv4, ns3::Ipv6, ns3::Udp, ns3::Quic, and ns3::Tcp classes.  The program will assert
     * if this method is called on a container with a node that already has
     * an Ipv4 object aggregated to it.
     *
     * \param c NodeContainer that holds the set of nodes on which to install the
     * new stacks.
     */
    void InstallQuic(NodeContainer c) const;

  private:
    /**
     * \brief create an object from its TypeId and aggregates it to the node
     * \param node the node
     * \param typeId the object TypeId
     */
    static void CreateAndAggregateObjectFromTypeId(Ptr<Node> node, const std::string typeId);
};

} // namespace ns3

#endif // QUIC_HELPER_H
