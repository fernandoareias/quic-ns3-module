check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        )
endif()

build_lib(
    LIBNAME quic
    SOURCE_FILES model/quic-bbr.cc
                 model/quic-connection-id.cc
                 model/quic-crypto-stream.cc
                 model/quic-cubic.cc
                 model/quic-congestion-ops.cc
                 model/quic-header.cc
                 model/quic-l4-protocol.cc
                 model/quic-l5-protocol.cc
                 model/quic-qlog-writer.cc
                 model/quic-socket.cc
                 model/quic-stream-id-tag.cc
                 model/quic-socket-base.cc
                 model/quic-socket-handshake.cc
                 model/quic-socket-factory.cc
                 model/quic-socket-rx-buffer.cc
                 model/quic-socket-tx-buffer.cc
                 model/quic-socket-tx-edf-scheduler.cc
                 model/quic-socket-tx-pfifo-scheduler.cc
                 model/quic-socket-tx-streamfifo-scheduler.cc
                 model/quic-socket-tx-roundrobin-scheduler.cc
                 model/quic-socket-tx-scheduler.cc
                 model/quic-stream.cc
                 model/quic-stream-base.cc
                 model/quic-stream-rx-buffer.cc
                 model/quic-stream-tx-buffer.cc
                 model/quic-subheader.cc
                 model/quic-tls-emulator.cc
                 model/quic-transport-parameters.cc
                 model/quic-wire.cc
                 helper/quic-helper.cc
    HEADER_FILES model/quic-stream-id-tag.h
                 model/quic-connection-id.h
                 model/quic-crypto-stream.h
                 model/quic-cubic.h
                 model/quic-bbr.h
                 model/quic-congestion-ops.h
                 model/quic-header.h
                 model/quic-l4-protocol.h
                 model/quic-l5-protocol.h
                 model/quic-qlog-writer.h
                 model/quic-socket.h
                 model/quic-socket-base.h
                 model/quic-socket-factory.h
                 model/quic-socket-rx-buffer.h
                 model/quic-socket-tx-buffer.h
                 model/quic-socket-tx-edf-scheduler.h
                 model/quic-socket-tx-pfifo-scheduler.h
                 model/quic-socket-tx-streamfifo-scheduler.h
                 model/quic-socket-tx-roundrobin-scheduler.h
                 model/quic-socket-tx-scheduler.h
                 model/quic-stream.h
                 model/quic-stream-base.h
                 model/quic-stream-rx-buffer.h
                 model/quic-stream-tx-buffer.h
                 model/quic-subheader.h
                 model/quic-tls-emulator.h
                 model/quic-transport-parameters.h
                 model/quic-wire.h
                 helper/quic-helper.h
    LIBRARIES_TO_LINK ${libcore}
                      ${libnetwork}
                      ${libinternet}
                      ${libtraffic-control}
                      ${libpoint-to-point}
    TEST_SOURCES test/quic-test-suite.cc
                 test/quic-features-test-suite.cc
                 test/quic-frames-test-suite.cc
                 test/quic-streams-test-suite.cc
                 test/quic-datagrams-test-suite.cc
                 test/quic-wire-test-suite.cc
                 test/quic-qlog-test-suite.cc
                 test/quic-handshake-test-suite.cc
                 test/quic-ecn-test-suite.cc
                 ${examples_as_tests_sources}
)
