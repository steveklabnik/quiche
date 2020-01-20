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

//! Quiche application utilities.
//!
//! This module provides some utility functions that are common to quiche
//! applications.
pub mod utils {
    /// Returns a String containing a pretty printed version of the `buf` slice
    pub fn hex_dump(buf: &[u8]) -> String {
        let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

        vec.join("")
    }

    /// ALPN helpers.
    ///
    /// This module contains constants and functions for working with ALPN.
    pub mod alpns {
        pub const HTTP_09: [&str; 3] = ["hq-24", "hq-23", "http/0.9"];
        pub const HTTP_3: [&str; 2] = ["h3-24", "h3-23"];

        pub fn length_prefixed(alpns: &[&str]) -> Vec<u8> {
            let mut out = Vec::new();

            for s in alpns {
                out.push(s.len() as u8);
                out.extend_from_slice(s.as_bytes());
            }

            out
        }
    }

    /// Contains commons arguments for creating a quiche QUIC connection.
    pub struct CommonArgs {
        pub alpns: Vec<u8>,
        pub max_data: u64,
        pub max_stream_data: u64,
        pub max_streams_bidi: u64,
        pub max_streams_uni: u64,
        pub dump_packet_path: Option<String>,
        pub no_grease: bool,
    }

    /// Creates a new `CommonArgs` structure using the provided [`Docopt`].
    ///
    /// The `Docopt` usage String needs to include the following:
    ///
    /// --http-version VERSION   HTTP version to use
    /// --max-data BYTES         Connection-wide flow control limit.
    /// --max-stream-data BYTES  Per-stream flow control limit.
    /// --max-streams-bidi STREAMS  Number of allowed concurrent streams.
    /// --max-streams-uni STREAMS   Number of allowed concurrent streams.
    /// --dump-packets PATH         Dump the incoming packets as files in the given directory.
    /// --no-grease                 Don't send GREASE.
    ///
    /// [`Docopt`]: https://docs.rs/docopt/1.1.0/docopt/
    impl CommonArgs {
        pub fn with_docopt(docopt: &docopt::Docopt) -> Self {
            let args = docopt.parse()
                .unwrap_or_else(|e| e.exit());

            let http_version = args.get_str("--http-version");
            let alpns = match http_version {
                "HTTP/0.9" => alpns::length_prefixed(&alpns::HTTP_09),

                "HTTP/3" => alpns::length_prefixed(&alpns::HTTP_3),

                "all" => [
                    alpns::length_prefixed(&alpns::HTTP_3),
                    alpns::length_prefixed(&alpns::HTTP_09),
                ]
                .concat(),

                _ => panic!("Unsupported HTTP version"),
            };

            let max_data = args.get_str("--max-data");
            let max_data = u64::from_str_radix(max_data, 10).unwrap();

            let max_stream_data = args.get_str("--max-stream-data");
            let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

            let max_streams_bidi = args.get_str("--max-streams-bidi");
            let max_streams_bidi = u64::from_str_radix(max_streams_bidi, 10).unwrap();

            let max_streams_uni = args.get_str("--max-streams-uni");
            let max_streams_uni = u64::from_str_radix(max_streams_uni, 10).unwrap();

            let dump_packet_path = if args.get_str("--dump-packets") != "" {
                Some(args.get_str("--dump-packets").to_string())
            } else {
                None
            };

            let no_grease = args.get_bool("--no-grease");

            CommonArgs {
                alpns,
                max_data,
                max_stream_data,
                max_streams_bidi,
                max_streams_uni,
                dump_packet_path,
                no_grease
            }
        }
    }
}
