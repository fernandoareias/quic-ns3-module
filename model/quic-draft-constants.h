/*
 * Copyright (c) 2026 Fernando Areias
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Fernando Areias <nando.calheirosx@gmail.com>
 */

#ifndef QUIC_DRAFT_CONSTANTS_H
#define QUIC_DRAFT_CONSTANTS_H

#include <cstdint>

/**
 * @file
 * The identifiers that drafts of the QUIC working group use before IANA assigns them. They are
 * kept in one place, with the revision of the draft they come from, to change them when the
 * drafts do.
 */

namespace ns3
{

/** draft-ietf-quic-receive-ts-04, Section 4: max_receive_timestamps_per_ack (temporary). */
constexpr uint64_t QUIC_TP_MAX_RECEIVE_TIMESTAMPS_PER_ACK = 0x1fed5311;
/** draft-ietf-quic-receive-ts-04, Section 4: receive_timestamps_exponent (temporary). */
constexpr uint64_t QUIC_TP_RECEIVE_TIMESTAMPS_EXPONENT = 0x1fed5312;
/** draft-ietf-quic-receive-ts-04, Section 5: ACK_RECEIVE_TIMESTAMPS without ECN counts. */
constexpr uint64_t QUIC_FRAME_ACK_RECEIVE_TIMESTAMPS = 0x03178307;
/** draft-ietf-quic-receive-ts-04, Section 5: ACK_RECEIVE_TIMESTAMPS with ECN counts. */
constexpr uint64_t QUIC_FRAME_ACK_RECEIVE_TIMESTAMPS_ECN = 0x03178308;

} // namespace ns3

#endif // QUIC_DRAFT_CONSTANTS_H
