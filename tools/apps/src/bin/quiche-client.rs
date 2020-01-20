// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::collections::HashMap;

use std::net::ToSocketAddrs;

use std::io::prelude::*;

use ring::rand::*;

use quiche_apps::utils::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const USAGE: &str = "Usage:
  quiche-client [options] URL...
  quiche-client -h | --help

Options:
  --method METHOD          Use the given HTTP request method [default: GET].
  --body FILE              Send the given file as request body.
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --http-version VERSION   HTTP version to use [default: all].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --dump-responses PATH    Dump response payload as files in the given directory.
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  -H --header HEADER ...   Add a request header.
  -n --requests REQUESTS   Send the given number of identical requests [default: 1].
  -h --help                Show this screen.
";

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = Args::with_docopt(&docopt);

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // We'll only connect to the first server provided in URL list.
    let connect_url = &args.urls[0];

    // Resolve server address.
    let peer_addr = connect_url.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
    socket.connect(peer_addr).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(args.version).unwrap();

    config.verify_peer(!args.no_verify);

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.set_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(true);

    if conn_args.no_grease {
        config.grease(false);
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    let mut http_conn = None;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(connect_url.domain(), &scid, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let write = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send(&out[..write]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    debug!("written {}", write);

    let req_start = std::time::Instant::now();

    let mut pkt_count = 0;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{}/{}.pkt", target_path, pkt_count);

                if let Ok(f) = std::fs::File::create(&path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(&buf[..len]).ok();
                }
            }

            pkt_count += 1;

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done reading");
                    break;
                },

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    break 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            report_http_incomplete(&http_conn, &req_start);

            break;
        }

        // Create a new HTTP connection once the QUIC connection is established.
        if conn.is_established() && http_conn.is_none() {
            let app_proto = conn.application_proto();
            let app_proto = &std::str::from_utf8(&app_proto).unwrap().to_owned();

            http_conn = Some(HttpConn::with_args(&args, &app_proto, &mut conn));
        }

        // If we have an HTTP connection, first issue the requests.
        if let Some(h_conn) = http_conn.as_mut() {
            h_conn.send_requests(&mut conn, &args.dump_response_path);
        }

        // If we have an HTTP connection, process received data
        if let Some(h_conn) = http_conn.as_mut() {
            h_conn.handle_responses(&mut conn, &mut buf, &req_start);
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send(&out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            report_http_incomplete(&http_conn, &req_start);

            break;
        }
    }
}

// Makes a buffered writer for the response body returned by the target URL. The
// file will have the same name as the resource's last path segment value.
// Multiple requests for the same URL are indiated by the value of `cardinal`,
// any value "N" greater than 1, will cause ".N" to be appended to the filename.
fn make_fd(
    url: &url::Url, target_path: &str, cardinal: u64,
) -> std::io::BufWriter<std::fs::File> {
    let resource = url.path_segments().map(|c| c.collect::<Vec<_>>()).unwrap();

    let mut path = format!("{}/{}", target_path, resource.iter().last().unwrap());

    if cardinal > 1 {
        path = format!("{}.{}", path, cardinal);
    }

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => panic!("Bad times: {}", e),
    }
}

fn report_http_incomplete(
    http_conn: &Option<HttpConn>, start: &std::time::Instant,
) {
    let (reqs_complete, reqs_count) = match &http_conn {
        Some(HttpConn::Http09Conn {
            reqs_complete,
            reqs,
            ..
        }) => (*reqs_complete, reqs.len()),

        Some(HttpConn::Http3Conn {
            reqs_complete,
            reqs,
            ..
        }) => (*reqs_complete, reqs.len()),

        None => (0, 0),
    };

    if reqs_complete != reqs_count {
        error!(
            "connection timed out after {:?} and only completed {}/{} requests",
            start.elapsed(),
            reqs_complete,
            reqs_count
        );
    }
}

// Represents an HTTP/0.9 formatted request.
struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
}

// Represents an HTTP/3 formatted request.
struct Http3Request {
    url: url::Url,
    cardinal: u64,
    hdrs: Vec<quiche::h3::Header>,
}

// Used for application tracking of HTTP requests and responses.
#[allow(clippy::large_enum_variant)]
enum HttpConn {
    Http09Conn {
        stream_id: u64,
        reqs_sent: usize,
        reqs_complete: usize,
        reqs: Vec<Http09Request>,
        fds: HashMap<u64, std::io::BufWriter<std::fs::File>>,
    },

    Http3Conn {
        h3_conn: quiche::h3::Connection,
        reqs_sent: usize,
        reqs_complete: usize,
        reqs: Vec<Http3Request>,
        body: Option<Vec<u8>>,
        fds: HashMap<u64, std::io::BufWriter<std::fs::File>>,
    },
}

impl HttpConn {
    fn with_args(
        args: &Args, app_proto: &str, conn: &mut quiche::Connection,
    ) -> Self {
        if alpns::HTTP_09.contains(&app_proto) {
            let mut reqs = Vec::new();
            for url in &args.urls {
                for i in 1..args.reqs_cardinal+1 {
                    let request_line = format!("GET {}\r\n", url.path());
                    reqs.push(Http09Request {
                        url: url.clone(),
                        cardinal: i,
                        request_line,
                    });
                }
            }

            HttpConn::Http09Conn {
                stream_id: 0,
                reqs_sent: 0,
                reqs_complete: 0,
                reqs,
                fds: HashMap::new(),
            }
        } else if alpns::HTTP_3.contains(&app_proto) {
            let mut reqs = Vec::new();
            for url in &args.urls {
                for i in 1..args.reqs_cardinal+1 {
                    let mut hdrs = vec![
                        quiche::h3::Header::new(":method", &args.method),
                        quiche::h3::Header::new(":scheme", url.scheme()),
                        quiche::h3::Header::new(
                            ":authority",
                            url.host_str().unwrap(),
                        ),
                        quiche::h3::Header::new(
                            ":path",
                            &url[url::Position::BeforePath..],
                        ),
                        quiche::h3::Header::new("user-agent", "quiche"),
                    ];

                    // Add custom headers to the request.
                    for header in &args.req_headers {
                        let header_split: Vec<&str> =
                            header.splitn(2, ": ").collect();
                        if header_split.len() != 2 {
                            panic!("malformed header provided - \"{}\"", header);
                        }

                        hdrs.push(quiche::h3::Header::new(
                            header_split[0],
                            header_split[1],
                        ));
                    }

                    if args.body.is_some() {
                        hdrs.push(quiche::h3::Header::new(
                            "content-length",
                            &args.body.as_ref().unwrap().len().to_string(),
                        ));
                    }

                    reqs.push(Http3Request {
                        url: url.clone(),
                        cardinal: i,
                        hdrs,
                    });
                }
            }

            HttpConn::Http3Conn {
                h3_conn: quiche::h3::Connection::with_transport(
                    conn,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
                reqs_sent: 0,
                reqs_complete: 0,
                reqs,
                body: args.body.clone(),
                fds: HashMap::new(),
            }
        } else {
            panic!("Negotiated unhandled protocol {:?}", app_proto);
        }
    }

    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        match self {
            HttpConn::Http09Conn {
                stream_id,
                reqs_sent,
                reqs,
                fds,
                ..
            } => {
                let mut reqs_done = 0;

                for req in reqs.iter().skip(*reqs_sent) {
                    info!("sending HTTP request {:?}", req.request_line);

                    match conn.stream_send(
                        *stream_id,
                        req.request_line.as_bytes(),
                        true,
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::StreamLimit) => {
                            debug!("not enough stream credits, retry later...");
                            break;
                        },

                        Err(e) => {
                            error!("failed to send request {:?}", e);
                            break;
                        },
                    };

                    if let Some(path) = target_path.as_ref() {
                        fds.insert(
                            *stream_id,
                            make_fd(&req.url, &path, req.cardinal),
                        );
                    }

                    *stream_id += 4;

                    reqs_done += 1;
                }

                *reqs_sent += reqs_done;
            },

            HttpConn::Http3Conn {
                h3_conn,
                reqs_sent,
                reqs,
                body,
                fds,
                ..
            } => {
                let mut reqs_done = 0;

                for req in reqs.iter().skip(*reqs_sent) {
                    info!("sending HTTP request {:?}", req.hdrs);

                    let s = match h3_conn.send_request(
                        conn,
                        &req.hdrs,
                        body.is_none(),
                    ) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::TransportError(
                            quiche::Error::StreamLimit,
                        )) => {
                            debug!("not enough stream credits, retry later...");
                            break;
                        },

                        Err(e) => {
                            error!("failed to send request {:?}", e);
                            break;
                        },
                    };

                    if let Some(path) = target_path.as_ref() {
                        fds.insert(s, make_fd(&req.url, path, req.cardinal));
                    }

                    if let Some(body) = &body {
                        if let Err(e) = h3_conn.send_body(conn, s, body, true) {
                            error!("failed to send request body {:?}", e);
                            break;
                        }
                    }

                    reqs_done += 1;
                }

                *reqs_sent += reqs_done;
            },
        }
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        match self {
            HttpConn::Http09Conn {
                fds,
                reqs_complete,
                reqs,
                ..
            } => {
                // Process all readable streams.
                for s in conn.readable() {
                    while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                        debug!("received {} bytes", read);

                        let stream_buf = &buf[..read];

                        debug!(
                            "stream {} has {} bytes (fin? {})",
                            s,
                            stream_buf.len(),
                            fin
                        );

                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(&stream_buf)
                        });

                        if let Some(f) = fds.get_mut(&s) {
                            f.write_all(&buf[..read]).ok();
                        }

                        // The server reported that it has no more data to send on
                        // a client-initiated
                        // bidirectional stream, which means
                        // we got the full response. If all responses are received
                        // then close the connection.
                        if &s % 4 == 0 && fin {
                            *reqs_complete += 1;
                            let reqs_count = reqs.len();

                            debug!(
                                "{}/{} responses received",
                                reqs_complete, reqs_count
                            );

                            if *reqs_complete == reqs_count {
                                info!(
                                    "{}/{} response(s) received in {:?}, closing...",
                                    reqs_complete,
                                    reqs_count,
                                    req_start.elapsed()
                                );

                                match conn.close(true, 0x00, b"kthxbye") {
                                    // Already closed.
                                    Ok(_) | Err(quiche::Error::Done) => (),

                                    Err(e) =>
                                        panic!("error closing conn: {:?}", e),
                                }

                                break;
                            }
                        }
                    }
                }
            },

            HttpConn::Http3Conn {
                h3_conn,
                fds,
                reqs_complete,
                reqs,
                ..
            } => {
                loop {
                    match h3_conn.poll(conn) {
                        Ok((
                            stream_id,
                            quiche::h3::Event::Headers { list, .. },
                        )) => {
                            info!(
                                "got response headers {:?} on stream id {}",
                                list, stream_id
                            );
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            if let Ok(read) =
                                h3_conn.recv_body(conn, stream_id, buf)
                            {
                                debug!(
                                    "got {} bytes of response data on stream {}",
                                    read, stream_id
                                );

                                print!("{}", unsafe {
                                    std::str::from_utf8_unchecked(&buf[..read])
                                });

                                if let Some(f) = fds.get_mut(&stream_id) {
                                    f.write_all(&buf[..read]).ok();
                                }
                            }
                        },

                        Ok((_stream_id, quiche::h3::Event::Finished)) => {
                            *reqs_complete += 1;
                            let reqs_count = reqs.len();

                            debug!(
                                "{}/{} responses received",
                                reqs_complete, reqs_count
                            );

                            if *reqs_complete == reqs_count {
                                info!(
                                    "{}/{} response(s) received in {:?}, closing...",
                                    reqs_complete,
                                    reqs_count,
                                    req_start.elapsed()
                                );

                                match conn.close(true, 0x00, b"kthxbye") {
                                    // Already closed.
                                    Ok(_) | Err(quiche::Error::Done) => (),

                                    Err(e) =>
                                        panic!("error closing conn: {:?}", e),
                                }

                                break;
                            }
                        },

                        Err(quiche::h3::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!("HTTP/3 processing failed: {:?}", e);

                            break;
                        },
                    }
                }
            },
        }
    }
}

// Application-specific arguments that compliment the `CommonArgs`.
struct Args {
    version: u32,
    dump_response_path: Option<String>,
    urls: Vec<url::Url>,
    reqs_cardinal: u64,
    req_headers: Vec<String>,
    no_verify: bool,
    body: Option<Vec<u8>>,
    method: String,
}

impl Args {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse()
            .unwrap_or_else(|e| e.exit());


        let version = args.get_str("--wire-version");
        let version = u32::from_str_radix(version, 16).unwrap();

        let dump_response_path = if args.get_str("--dump-responses") != "" {
            Some(args.get_str("--dump-responses").to_string())
        } else {
            None
        };

        // URLs (can be multiple)
        let urls: Vec<url::Url> = args
            .get_vec("URL")
            .into_iter()
            .map(|x| url::Url::parse(x).unwrap())
            .collect();

        // Request headers (can be multiple).
        let req_headers = args
            .get_vec("--header")
            .into_iter()
            .map(|x| x.to_string())
            .collect();

        let reqs_cardinal = args.get_str("--requests");
        let reqs_cardinal = u64::from_str_radix(reqs_cardinal, 10).unwrap();

        let no_verify = args.get_bool("--no-verify");

        let body = if args.get_bool("--body") {
            std::fs::read(args.get_str("--body")).ok()
        } else {
            None
        };

        let method = args.get_str("--method").to_string();

        Args {
            version,
            dump_response_path,
            urls,
            req_headers,
            reqs_cardinal,
            no_verify,
            body,
            method,
        }
    }
}
