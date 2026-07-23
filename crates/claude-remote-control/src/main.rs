use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, error::ErrorKind};
use remora_claude_remote_control::{
    BridgeApiClient, BridgeEnvironmentRegistration, ClaudeAuthState, ClaudeCredentialStore,
    DaemonConfig, EndpointConfig, EnvironmentKind, PermissionMode, RemoteControlAvailability,
    RemoteControlDaemonEntry, RemoteEvent, SessionContext, SessionCreateRequest, SessionSource,
    SpawnMode, read_session_ingress_token_override,
};
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

#[derive(Debug, Parser)]
#[command(
    name = "remora-claude-remote-control",
    about = "Claude Code Remote Control API and credential inspection CLI"
)]
struct Cli {
    #[arg(long, global = true)]
    base_url: Option<Url>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Register(RegisterArgs),
    Deregister(EnvironmentIdArgs),
    Poll(PollArgs),
    Work {
        #[command(subcommand)]
        command: WorkCommand,
    },
    Sessions {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Worker {
        #[command(subcommand)]
        command: WorkerCommand,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    Raw(RawArgs),
    Tui,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Refresh,
}

#[derive(Debug, Args)]
struct RegisterArgs {
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[arg(long)]
    branch: Option<String>,
    #[arg(long = "git-repo-url")]
    git_repo_url: Option<String>,
    #[arg(long, default_value_t = 1)]
    max_sessions: usize,
    #[arg(long = "reuse-environment-id")]
    reuse_environment_id: Option<String>,
}

#[derive(Debug, Args)]
struct EnvironmentIdArgs {
    environment_id: String,
}

#[derive(Debug, Args)]
struct PollArgs {
    environment_id: String,
    #[arg(long)]
    reclaim_older_than_ms: Option<u64>,
}

#[derive(Debug, Subcommand)]
enum WorkCommand {
    Ack(WorkIdArgs),
    Heartbeat(WorkIdArgs),
    Stop {
        environment_id: String,
        work_id: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
struct WorkIdArgs {
    environment_id: String,
    work_id: String,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    List {
        #[arg(long, alias = "cursor")]
        page: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Create {
        environment_id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long = "permission-mode")]
        permission_mode: Option<String>,
        #[arg(long = "message")]
        initial_message: Option<String>,
    },
    Get {
        session_id: String,
    },
    Update {
        session_id: String,
        body_json: String,
    },
    Delete {
        session_id: String,
    },
    Archive {
        session_id: String,
    },
    Events {
        session_id: String,
        #[arg(long, alias = "cursor")]
        page: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Send {
        session_id: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        event_json: Option<String>,
    },
    Control {
        session_id: String,
        request_json: String,
    },
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    Register(WorkerBaseArgs),
    State(WorkerBaseArgs),
    Init {
        #[command(flatten)]
        base: WorkerBaseArgs,
        worker_epoch: String,
        #[arg(long)]
        state_json: Option<String>,
    },
    Heartbeat {
        #[command(flatten)]
        base: WorkerBaseArgs,
        session_id: String,
        worker_epoch: String,
    },
    Events {
        #[command(flatten)]
        base: WorkerBaseArgs,
        worker_epoch: String,
        events_json: String,
    },
    InternalEvents {
        #[command(flatten)]
        base: WorkerBaseArgs,
        #[arg(long)]
        subagents: bool,
    },
    DeliveryAck {
        #[command(flatten)]
        base: WorkerBaseArgs,
        worker_epoch: String,
        updates_json: String,
    },
}

#[derive(Debug, Args)]
struct WorkerBaseArgs {
    session_base_url: String,
    #[arg(long = "session-ingress-token")]
    session_ingress_token: Option<String>,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    List,
    Add {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum)]
        spawn: Option<SpawnMode>,
    },
    Remove {
        name_or_dir: String,
    },
}

#[derive(Debug, Args)]
struct RawArgs {
    method: String,
    path: String,
    #[arg(long)]
    body_json: Option<String>,
    #[arg(long, default_value = "remote-control")]
    beta: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Tui => run_tui(cli.base_url).await,
        command => execute_command(cli.base_url, command).await,
    }
}

async fn execute_command(base_url: Option<Url>, command: Command) -> Result<()> {
    match command {
        Command::Auth { command } => run_auth(command).await,
        Command::Register(args) => {
            let client = load_client(base_url).await?;
            let response = client.register_environment(&registration(args)?).await?;
            print_json(&response)
        }
        Command::Deregister(args) => {
            let client = load_client(base_url).await?;
            client.deregister_environment(&args.environment_id).await?;
            println!("deregistered {}", args.environment_id);
            Ok(())
        }
        Command::Poll(args) => {
            let client = load_client(base_url).await?;
            let work = client
                .poll_for_work(&args.environment_id, args.reclaim_older_than_ms)
                .await?;
            print_json(&work)
        }
        Command::Work { command } => run_work(base_url, command).await,
        Command::Sessions { command } => run_sessions(base_url, command).await,
        Command::Worker { command } => run_worker(base_url, command).await,
        Command::Daemon { command } => run_daemon(command).await,
        Command::Raw(args) => run_raw(base_url, args).await,
        Command::Tui => bail!("already in TUI; use `quit` to exit"),
    }
}

async fn run_auth(command: AuthCommand) -> Result<()> {
    let store = ClaudeCredentialStore::new();
    match command {
        AuthCommand::Status { json } => {
            let state = store.load_auth_state().await?;
            let status = AuthStatusOutput::from_state(&state);
            if json {
                print_json(&status)
            } else {
                println!("token: {}", yes_no(status.has_access_token));
                println!("source: {:?}", status.access_token_source);
                println!("store: {:?}", status.credential_backend);
                println!(
                    "organization_uuid: {}",
                    yes_no(status.has_organization_uuid)
                );
                println!(
                    "trusted_device_token: {}",
                    yes_no(status.trusted_device_token_present)
                );
                println!("available: {}", yes_no(status.available));
                if let Some(reason) = status.disabled_reason {
                    println!("disabled_reason: {reason}");
                }
                Ok(())
            }
        }
        AuthCommand::Refresh => {
            let refreshed = store.refresh_oauth_token(None).await?;
            match refreshed {
                Some(oauth) => {
                    println!(
                        "refreshed oauth token; scopes={}",
                        if oauth.scopes.is_empty() {
                            "(none)".to_string()
                        } else {
                            oauth.scopes.join(",")
                        }
                    );
                }
                None => println!("no refreshable claudeAiOauth token found"),
            }
            Ok(())
        }
    }
}

async fn run_work(base_url: Option<Url>, command: WorkCommand) -> Result<()> {
    let client = load_client(base_url).await?;
    match command {
        WorkCommand::Ack(args) => {
            client
                .acknowledge_work(&args.environment_id, &args.work_id)
                .await?;
            println!("acknowledged {}", args.work_id);
        }
        WorkCommand::Heartbeat(args) => {
            let response = client
                .heartbeat_work(&args.environment_id, &args.work_id)
                .await?;
            print_json(&response)?;
        }
        WorkCommand::Stop {
            environment_id,
            work_id,
            force,
        } => {
            client.stop_work(&environment_id, &work_id, force).await?;
            println!("stopped {work_id}");
        }
    }
    Ok(())
}

async fn run_sessions(base_url: Option<Url>, command: SessionCommand) -> Result<()> {
    let client = load_client(base_url).await?;
    match command {
        SessionCommand::List { page, limit } => {
            print_json(&client.list_sessions(page.as_deref(), limit).await?)?;
        }
        SessionCommand::Create {
            environment_id,
            title,
            cwd,
            permission_mode,
            initial_message,
        } => {
            let events = match initial_message {
                Some(text) => vec![RemoteEvent::user_text(text)],
                None => Vec::new(),
            };
            let request = SessionCreateRequest {
                events,
                session_context: cwd.map(|cwd| SessionContext {
                    cwd: Some(cwd),
                    git_repo_url: None,
                    branch: None,
                    extra: Default::default(),
                }),
                environment_id,
                source: SessionSource::RemoteControl,
                permission_mode: permission_mode.map(PermissionMode::new),
                title,
            };
            print_json(&client.create_session(&request).await?)?;
        }
        SessionCommand::Get { session_id } => {
            print_json(&client.fetch_session(&session_id).await?)?;
        }
        SessionCommand::Update {
            session_id,
            body_json,
        } => {
            let body: Value = serde_json::from_str(&body_json)?;
            print_json(&client.update_session(&session_id, &body).await?)?;
        }
        SessionCommand::Delete { session_id } => {
            client.delete_session(&session_id).await?;
            println!("deleted {session_id}");
        }
        SessionCommand::Archive { session_id } => {
            client.archive_session(&session_id).await?;
            println!("archived {session_id}");
        }
        SessionCommand::Events {
            session_id,
            page,
            limit,
        } => {
            print_json(
                &client
                    .get_session_events(&session_id, page.as_deref(), limit)
                    .await?,
            )?;
        }
        SessionCommand::Send {
            session_id,
            text,
            event_json,
        } => {
            let event = match (text, event_json) {
                (Some(text), None) => RemoteEvent::user_text(text),
                (None, Some(raw)) => serde_json::from_str::<RemoteEvent>(&raw)?,
                _ => bail!("provide exactly one of --text or --event-json"),
            };
            client.post_session_events(&session_id, vec![event]).await?;
            println!("sent event to {session_id}");
        }
        SessionCommand::Control {
            session_id,
            request_json,
        } => {
            let request: Value = serde_json::from_str(&request_json)?;
            let request_id = uuid::Uuid::now_v7().to_string();
            client
                .post_session_events(
                    &session_id,
                    vec![RemoteEvent::Unknown(json!({
                        "type": "control_request",
                        "request_id": request_id,
                        "request": request,
                    }))],
                )
                .await?;
            println!("{request_id}");
        }
    }
    Ok(())
}

async fn run_worker(base_url: Option<Url>, command: WorkerCommand) -> Result<()> {
    let client = load_client(base_url).await?;
    match command {
        WorkerCommand::Register(base) => {
            let token = worker_token(&base).await?;
            print_json(
                &client
                    .worker_register(&base.session_base_url, &token)
                    .await?,
            )?;
        }
        WorkerCommand::State(base) => {
            let token = worker_token(&base).await?;
            print_json(&client.worker_state(&base.session_base_url, &token).await?)?;
        }
        WorkerCommand::Init {
            base,
            worker_epoch,
            state_json,
        } => {
            let token = worker_token(&base).await?;
            let state = match state_json {
                Some(value) => serde_json::from_str(&value)?,
                None => Default::default(),
            };
            client
                .worker_init(
                    &base.session_base_url,
                    &token,
                    &remora_claude_remote_control::wire::WorkerInitRequest {
                        worker_epoch,
                        state,
                    },
                )
                .await?;
            println!("worker initialized");
        }
        WorkerCommand::Heartbeat {
            base,
            session_id,
            worker_epoch,
        } => {
            let token = worker_token(&base).await?;
            client
                .worker_heartbeat(
                    &base.session_base_url,
                    &token,
                    &remora_claude_remote_control::wire::WorkerHeartbeatRequest {
                        session_id,
                        worker_epoch,
                    },
                )
                .await?;
            println!("worker heartbeat sent");
        }
        WorkerCommand::Events {
            base,
            worker_epoch,
            events_json,
        } => {
            let token = worker_token(&base).await?;
            let events: Vec<RemoteEvent> = serde_json::from_str(&events_json)?;
            client
                .worker_events(
                    &base.session_base_url,
                    &token,
                    &remora_claude_remote_control::wire::WorkerEventsRequest {
                        worker_epoch,
                        events,
                    },
                )
                .await?;
            println!("worker events sent");
        }
        WorkerCommand::InternalEvents { base, subagents } => {
            let token = worker_token(&base).await?;
            print_json(
                &client
                    .get_worker_internal_events(&base.session_base_url, &token, subagents)
                    .await?,
            )?;
        }
        WorkerCommand::DeliveryAck {
            base,
            worker_epoch,
            updates_json,
        } => {
            let token = worker_token(&base).await?;
            let updates = serde_json::from_str(&updates_json)?;
            client
                .worker_delivery_ack(
                    &base.session_base_url,
                    &token,
                    &remora_claude_remote_control::wire::WorkerDeliveryAckRequest {
                        worker_epoch,
                        updates,
                    },
                )
                .await?;
            println!("worker delivery ack sent");
        }
    }
    Ok(())
}

async fn run_daemon(command: DaemonCommand) -> Result<()> {
    let store = ClaudeCredentialStore::new();
    let path = store.paths().config_dir.join("daemon.json");
    let mut config = DaemonConfig::load(&path).await?;
    match command {
        DaemonCommand::List => print_json(&config.remote_control),
        DaemonCommand::Add { dir, name, spawn } => {
            config.upsert(RemoteControlDaemonEntry {
                dir: absolutize(dir)?,
                name,
                spawn_mode: spawn,
            });
            config.save(&path).await?;
            println!("updated {}", path.display());
            Ok(())
        }
        DaemonCommand::Remove { name_or_dir } => {
            let removed = config.remove_by_name_or_dir(&name_or_dir);
            config.save(&path).await?;
            if let Some(entry) = removed {
                println!("removed {}", entry.dir.display());
            } else {
                println!("no matching remoteControl daemon entry");
            }
            Ok(())
        }
    }
}

async fn run_raw(base_url: Option<Url>, args: RawArgs) -> Result<()> {
    let client = load_client(base_url).await?;
    let method: Method = args.method.parse().context("invalid HTTP method")?;
    let body = args
        .body_json
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()?;
    let beta = match args.beta.as_str() {
        "environments" => remora_claude_remote_control::RequestBeta::Environments,
        "managed-agents" => remora_claude_remote_control::RequestBeta::ManagedAgents,
        "both" | "remote-control-and-managed-agents" => {
            remora_claude_remote_control::RequestBeta::RemoteControlAndManagedAgents
        }
        "remote-control" | "ccr-byoc" => remora_claude_remote_control::RequestBeta::RemoteControl,
        other => bail!("unknown beta set: {other}"),
    };
    let response: Value = client
        .raw_json_path(method, &args.path, body.as_ref(), beta)
        .await?;
    print_json(&response)
}

async fn run_tui(base_url: Option<Url>) -> Result<()> {
    println!("Claude Remote Control TUI");
    println!(
        "type any CLI command without the binary name; examples: auth status, register --dir ., sessions list, worker register <url>, daemon list, raw GET /v1/sessions"
    );
    println!("use `<command> --help` for command help; use `quit` to exit");
    loop {
        print!("claude-rc> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "quit" | "exit" | "q") {
            break;
        }
        if line == "help" {
            print_tui_help();
            continue;
        }
        if let Err(err) = handle_tui_line(base_url.clone(), line).await {
            eprintln!("error: {err:#}");
        }
    }
    Ok(())
}

async fn handle_tui_line(base_url: Option<Url>, line: &str) -> Result<()> {
    let mut tokens = split_tui_line(line)?;
    if tokens.is_empty() {
        return Ok(());
    }
    expand_tui_aliases(&mut tokens);
    let mut argv = Vec::with_capacity(tokens.len() + 1);
    argv.push("remora-claude-remote-control".to_string());
    argv.extend(tokens);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let command_base_url = cli.base_url.or(base_url);
    if matches!(cli.command, Command::Tui) {
        println!("already in TUI; use `quit` to exit");
        return Ok(());
    }
    execute_command(command_base_url, cli.command).await
}

fn print_tui_help() {
    println!("auth status [--json]");
    println!("auth refresh");
    println!("register --dir <path> [--name <name>] [--branch <branch>] [--max-sessions <n>]");
    println!("deregister <environment_id>");
    println!("poll <environment_id> [--reclaim-older-than-ms <ms>]");
    println!("work ack|heartbeat <environment_id> <work_id>");
    println!("work stop <environment_id> <work_id> [--force]");
    println!("sessions list|get|create|update|delete|archive|events|send|control ...");
    println!("worker register|state|init|heartbeat|events|internal-events|delivery-ack ...");
    println!("daemon list|add|remove ...");
    println!("raw <METHOD> <PATH> [--body-json <json>] [--beta <set>]");
    println!("Aliases: status, get, events, send, archive, ack, heartbeat, stop");
}

fn expand_tui_aliases(tokens: &mut Vec<String>) {
    let Some(first) = tokens.first().map(String::as_str) else {
        return;
    };
    let prefix: &[&str] = match first {
        "status" => &["auth", "status"],
        "refresh-auth" => &["auth", "refresh"],
        "get" => &["sessions", "get"],
        "events" => &["sessions", "events"],
        "send" => &["sessions", "send"],
        "archive" => &["sessions", "archive"],
        "list-sessions" => &["sessions", "list"],
        "control" => &["sessions", "control"],
        "ack" => &["work", "ack"],
        "heartbeat" => &["work", "heartbeat"],
        "stop" => &["work", "stop"],
        _ => return,
    };
    tokens.remove(0);
    for part in prefix.iter().rev() {
        tokens.insert(0, (*part).to_string());
    }
}

fn split_tui_line(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote = None;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if let Some(q) = quote {
        bail!("unterminated {q} quote");
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

async fn load_client(base_url: Option<Url>) -> Result<BridgeApiClient> {
    let store = ClaudeCredentialStore::new();
    let state = store.load_auth_state().await?;
    let auth = state.bridge_auth().context(
        "missing Claude Remote Control OAuth token or organization UUID; run `claude auth login`",
    )?;
    let trusted = auth.trusted_device_token.clone();
    let org = auth.organization_uuid.clone();
    let base_url =
        base_url.unwrap_or_else(|| EndpointConfig::for_kind(EnvironmentKind::Prod).base_api_url);
    Ok(BridgeApiClient::builder(base_url, auth)
        .auth_refresh_callback(store.auth_refresh_callback(org, trusted))
        .build())
}

fn registration(args: RegisterArgs) -> Result<BridgeEnvironmentRegistration> {
    let dir = absolutize(args.dir)?;
    let machine_name = args.name.unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|name| name.into_string().ok())
            .unwrap_or_else(|| "remote-control".to_string())
    });
    let mut registration = BridgeEnvironmentRegistration::new(machine_name, dir);
    registration.branch = args.branch;
    registration.git_repo_url = args.git_repo_url;
    registration.max_sessions = args.max_sessions;
    registration.environment_id = args.reuse_environment_id;
    Ok(registration)
}

async fn worker_token(args: &WorkerBaseArgs) -> Result<String> {
    args.session_ingress_token
        .clone()
        .or(read_session_ingress_token_override().await?)
        .context("missing session ingress token; pass --session-ingress-token")
}

fn absolutize(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[derive(Debug, Serialize)]
struct AuthStatusOutput {
    access_token_source: remora_claude_remote_control::AccessTokenSource,
    credential_backend: remora_claude_remote_control::CredentialBackend,
    has_access_token: bool,
    has_organization_uuid: bool,
    trusted_device_token_present: bool,
    available: bool,
    disabled_reason: Option<String>,
}

impl AuthStatusOutput {
    fn from_state(state: &ClaudeAuthState) -> Self {
        let availability = RemoteControlAvailability::from_context(&state.auth_context());
        Self {
            access_token_source: state.access_token_source,
            credential_backend: state.credential_backend,
            has_access_token: state.has_access_token,
            has_organization_uuid: state.organization_uuid.is_some(),
            trusted_device_token_present: state.trusted_device_token_present,
            available: availability.available,
            disabled_reason: availability.disabled_reason.map(|reason| reason.message()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse_tui_line_for_test(line: &str) {
        let mut tokens = split_tui_line(line).unwrap();
        expand_tui_aliases(&mut tokens);
        let mut argv = Vec::with_capacity(tokens.len() + 1);
        argv.push("remora-claude-remote-control".to_string());
        argv.extend(tokens);
        Cli::try_parse_from(argv).unwrap_or_else(|err| panic!("{line:?} did not parse: {err}"));
    }

    #[test]
    fn top_level_help_exposes_every_command_group() {
        let help = Cli::command().render_long_help().to_string();
        for command in [
            "auth",
            "register",
            "deregister",
            "poll",
            "work",
            "sessions",
            "worker",
            "daemon",
            "raw",
            "tui",
        ] {
            assert!(
                help.contains(command),
                "top-level help missing command {command}"
            );
        }
    }

    #[test]
    fn tui_reparser_accepts_all_command_families_and_aliases() {
        for line in [
            "auth status",
            "auth status --json",
            "auth refresh",
            "register --dir . --name local --branch main --max-sessions 2",
            "deregister env_1",
            "poll env_1 --reclaim-older-than-ms 5000",
            "work ack env_1 work_1",
            "work heartbeat env_1 work_1",
            "work stop env_1 work_1 --force",
            "sessions list --limit 5 --page page_2",
            "sessions list --limit 5 --cursor page_2",
            "sessions get sess_1",
            "sessions create env_1 --title test --cwd . --permission-mode bypassPermissions --message hi",
            "sessions update sess_1 {\"title\":\"new\"}",
            "sessions delete sess_1",
            "sessions archive sess_1",
            "sessions events sess_1 --limit 10 --page page_2",
            "sessions events sess_1 --limit 10 --cursor page_2",
            "sessions send sess_1 --text hi",
            "sessions control sess_1 {\"subtype\":\"interrupt\"}",
            "worker register https://example.test/session --session-ingress-token tok",
            "worker state https://example.test/session --session-ingress-token tok",
            "worker init https://example.test/session epoch_1 --session-ingress-token tok",
            "worker heartbeat https://example.test/session sess_1 epoch_1 --session-ingress-token tok",
            "worker events https://example.test/session epoch_1 [] --session-ingress-token tok",
            "worker internal-events https://example.test/session --subagents --session-ingress-token tok",
            "worker delivery-ack https://example.test/session epoch_1 [] --session-ingress-token tok",
            "daemon list",
            "daemon add --dir . --name local --spawn worktree",
            "daemon remove local",
            "raw GET /v1/sessions",
            "status",
            "refresh-auth",
            "get sess_1",
            "events sess_1",
            "send sess_1 --text hi",
            "archive sess_1",
            "list-sessions",
            "control sess_1 {\"subtype\":\"interrupt\"}",
            "ack env_1 work_1",
            "heartbeat env_1 work_1",
            "stop env_1 work_1",
        ] {
            parse_tui_line_for_test(line);
        }
    }
}
