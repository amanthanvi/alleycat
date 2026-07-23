const APP: remora_host::App = remora_host::App {
    binary_name: "remora-link",
    qualifier: "com",
    organization: "remora",
    application: "remora-link",
    label: "com.remora.link",
    version: env!("CARGO_PKG_VERSION"),
};

fn main() -> anyhow::Result<()> {
    APP.run()
}
