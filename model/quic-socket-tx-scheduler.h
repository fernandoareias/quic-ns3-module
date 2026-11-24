/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Umberto Paro <umberto.paro@me.com>
 */

#ifndef QUICSOCKETTXSCHEDULER_H
#define QUICSOCKETTXSCHEDULER_H

#include "quic-socket.h"

#include <queue>
#include <vector>

namespace ns3
{

class QuicSocketTxItem;

/**
 * \ingroup quic
 *
 * \brief Tx item for QUIC with priority
 */
class QuicSocketTxScheduleItem : public Object
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    QuicSocketTxScheduleItem(uint64_t id, uint64_t off, double p, Ptr<QuicSocketTxItem> it);
    QuicSocketTxScheduleItem(const QuicSocketTxScheduleItem& other);

    /**
     *  Compare \p this to another QuicSocketTxScheduleItem
     *
     *  \param [in] o The other item
     *  \return -1,0,+1 if `this < o`, `this == o`, or `this > o`
     */
    int Compare(const QuicSocketTxScheduleItem& o) const;

    inline bool operator<(const QuicSocketTxScheduleItem& other) const
    {
        return Compare(other) < 0;
    }

    inline bool operator>(const QuicSocketTxScheduleItem& other) const
    {
        return Compare(other) > 0;
    }

    inline bool operator<=(const QuicSocketTxScheduleItem& other) const
    {
        return Compare(other) <= 0;
    }

    inline bool operator>=(const QuicSocketTxScheduleItem& other) const
    {
        return Compare(other) >= 0;
    }

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    Ptr<QuicSocketTxItem> GetItem() const;

    /**
     * \brief Get the ID of the stream the item belongs to.
     * \return the stream ID
     */
    uint64_t GetStreamId() const;

    /**
     * \brief Get the offset of the item in the stream.
     * \return the offset
     */
    uint64_t GetOffset() const;

    /**
     * \brief Get the priority.
     * \return the item priority
     */
    double GetPriority() const;

    /**
     * \brief Change the priority of the item.
     * \param priority the new priority
     */
    void SetPriority(double priority);

  private:
    uint64_t m_streamId;          //!< ID of the stream the item belongs to
    uint64_t m_offset;            //!< offset on the stream
    double m_priority;            //!< Priority level of the item (lowest is sent first)
    Ptr<QuicSocketTxItem> m_item; //!< TxItem containing the packet
};

class CompareScheduleItems
{
  public:
    bool operator()(Ptr<QuicSocketTxScheduleItem> ita, Ptr<QuicSocketTxScheduleItem> itb)
    {
        return (*ita) > (*itb);
    }
};

/**
 * \ingroup quic
 *
 * \brief Tx socket buffer for QUIC
 */
class QuicSocketTxScheduler : public Object
{
  public:
    QuicSocketTxScheduler();
    QuicSocketTxScheduler(const QuicSocketTxScheduler& other);
    virtual ~QuicSocketTxScheduler(void);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId(void);

    /**
     * Add a tx item to the scheduling list (default behavior: FIFO scheduling)
     *
     * \param item a smart pointer to a transmission item
     * \param retx true if the transmission item is being retransmitted
     */
    virtual void Add(Ptr<QuicSocketTxItem> item, bool retx);

    /**
     * \brief Get the next scheduled packet with a specified size
     *
     * \param numBytes number of bytes of the QuicSocketTxItem requested
     * \return the item that contains the right packet
     */
    Ptr<QuicSocketTxItem> GetNewSegment(uint32_t numBytes);

    /**
     * Returns the total number of bytes in the application buffer
     *
     * \return the total number of bytes in the application buffer
     */
    uint32_t AppSize(void) const;
    /**
     * Add a schedule tx item to the scheduling list
     *
     * \param item a scheduling item with priority
     * \param retx true if the item is being retransmitted
     */
    void AddScheduleItem(Ptr<QuicSocketTxScheduleItem> item, bool retx);

    /**
     * \brief Set the send priority of a stream (msquic QUIC_PARAM_STREAM_PRIORITY: higher goes
     * first)
     *
     * Only schedulers that honour stream priorities act on it.
     * \param streamId the stream
     * \param priority 0..65535, default 0x7FFF
     */
    virtual void SetStreamPriority(uint64_t streamId, uint16_t priority);

    /**
     * \brief Tell the scheduler that a stream holds (or no longer holds) unsent application data,
     * wherever that data is buffered. msquic keeps such a stream in its send list.
     * \param streamId the stream
     * \param backlogged true while data remains
     */
    virtual void OnStreamBacklog(uint64_t streamId, bool backlogged);

  protected:
    /**
     * \brief Called when bytes of a stream enter the scheduling list
     * \param streamId the stream
     * \param bytes number of bytes
     */
    virtual void OnQueued(uint64_t streamId, uint32_t bytes);

    /**
     * \brief Called when bytes of a stream leave the scheduling list
     * \param streamId the stream
     * \param bytes number of bytes
     */
    virtual void OnDequeued(uint64_t streamId, uint32_t bytes);

    /**
     * \\brief Called with the scheduling key of every item taken from the list
     * \\param priority the key the item was queued with
     */
    virtual void OnItemServed(double priority);

  private:
    typedef std::priority_queue<Ptr<QuicSocketTxScheduleItem>,
                                std::vector<Ptr<QuicSocketTxScheduleItem>>,
                                CompareScheduleItems>
        QuicTxPacketList; //!< container for data stored in the buffer
    QuicTxPacketList m_appList;
    uint32_t m_appSize;
};

} // namespace ns3

#endif /* QUIC_SOCKET_TX_SCHEDULER_H */
