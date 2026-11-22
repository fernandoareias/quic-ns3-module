build_lib_example(
    NAME quic-example
    SOURCE_FILES quic-example.cc
    LIBRARIES_TO_LINK ${libquic}
                      ${libcore}
                      ${libnetwork}
                      ${libinternet}
                      ${libpoint-to-point}
                      ${libapplications}
)

build_lib_example(
    NAME quic-video-streaming
    SOURCE_FILES quic-video-streaming.cc
    LIBRARIES_TO_LINK ${libquic}
                      ${libcore}
                      ${libnetwork}
                      ${libinternet}
                      ${libpoint-to-point}
                      ${libapplications}
)
