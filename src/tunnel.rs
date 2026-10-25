// TODO(Phase 8): client side — local TCP listener → QUIC streams.
//   `pub async fn run_client_side(conn: quinn::Connection, listen_port: u16) -> anyhow::Result<()>`
// TODO(Phase 9): server side — QUIC streams → TCP connections to remote target.
//   `pub async fn run_server_side(conn: quinn::Connection, target_addr: SocketAddr) -> anyhow::Result<()>`
