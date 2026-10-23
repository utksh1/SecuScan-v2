// Debug: query github.com MX through the hand-rolled DNS client.
use secuscan_exec::native::dns::{self, rtype};

#[tokio::main]
async fn main() {
    let server = dns::system_server().expect("no resolver");
    println!("resolver: {server}");
    for (name, rt) in [
        ("github.com", rtype::MX),
        ("github.com", rtype::A),
        ("google.com", rtype::MX),
        ("github.com", rtype::NS),
    ] {
        match dns::query(server, name, rt).await {
            Ok(recs) => {
                println!("{name} {} -> {} record(s)", rtype::name(rt), recs.len());
                for r in recs {
                    println!("   ttl={} data={}", r.ttl, r.data);
                }
            }
            Err(e) => println!("{name} {} -> ERROR {e:?}", rtype::name(rt)),
        }
    }
}
