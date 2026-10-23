//! SecuScan MCP server entrypoint.

use secuscan_mcp::{run_http, run_stdio, Cli, SecuScanClient};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secuscan_mcp=info".into()),
        )
        // Log to stderr only — stdout is reserved for JSON-RPC.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let client = SecuScanClient::with_creds(cli.api_url, cli.api_key, cli.email, cli.password);

    if let Some(bind) = cli.http {
        run_http(client, bind).await
    } else {
        run_stdio(client).await
    }
}
