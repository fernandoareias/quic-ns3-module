/*
 * Copyright (c) 2008 INRIA
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 * Author: Faker Moatamri <faker.moatamri@sophia.inria.fr>
 */

#include "quic-helper.h"

#include "ns3/log.h"
#include "ns3/object-factory.h"
#include "ns3/node.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicHelper");

void
QuicHelper::InstallQuic(NodeContainer c) const
{
    for (NodeContainer::Iterator i = c.Begin(); i != c.End(); ++i)
    {
        Install(*i);
        CreateAndAggregateObjectFromTypeId(*i, "ns3::QuicL4Protocol");
        NS_LOG_INFO("QuicHelper: installed QUIC stack on node " << (*i)->GetId());
    }
}

void
QuicHelper::CreateAndAggregateObjectFromTypeId(Ptr<Node> node, const std::string typeId)
{
    ObjectFactory factory;
    factory.SetTypeId(typeId);
    Ptr<Object> protocol = factory.Create<Object>();
    node->AggregateObject(protocol);
}

} // namespace ns3
