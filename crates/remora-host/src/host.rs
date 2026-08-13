use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use iroh::endpoint::QuicTransportConfig;
use iroh::endpoint::{IdleTimeout, VarInt, presets};
use iroh::{Endpoint, SecretKey};
use tokio::sync::{Notify, Semaphore};
use tracing::{info, warn};

use crate::agents::AgentManager;
use crate::catalog::{HostCatalogStore, WorkIntentPreparation};
use crate::framing::{
    MAX_REMORA_LINK_V2_FRAME_BYTES, read_json_frame_bounded, write_json_frame_bounded,
};
use crate::pairing_v2::{
    AuthorizationContextV2, EnrollmentOutcomeV2, ErrorCodeV2, PROTOCOL_VERSION_V2, PairingManager,
    ProofV2, REMORA_LINK_ALPN, RedeemError, RequestV2, ResponseV2, RestartPreparationV2,
    RestartResultV2, RestartStatusV2, RevocationMutationV2, WorkIntentReceiptV2,
    WorkIntentStatusV2,
};
use crate::protocol::SessionInfo;
use crate::stream::IrohStream;
use remora_bridge_core::command_center::ThreadId;

const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const MAX_CONCURRENT_CONNECTIONS_PER_ENDPOINT: usize = 8;
const MAX_CONCURRENT_STREAMS: usize = 256;
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 8;
const INITIAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const REMORA_LINK_CONNECT_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Run bounded connect setup while retaining its authorization fence.
///
/// The fence is released on success, setup failure, cancellation, or timeout.
/// Keeping this helper generic makes the liveness invariant directly testable
/// without constructing a network connection.
pub(crate) async fn run_bounded_connect_setup<G, F, T>(
    fence: G,
    timeout: Duration,
    setup: F,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: Future<Output = T>,
{
    let result = tokio::time::timeout(timeout, setup).await;
    drop(fence);
    result
}

#[derive(Default)]
struct EndpointConnectionQuota {
    counts: StdMutex<HashMap<String, usize>>,
}

impl EndpointConnectionQuota {
    fn try_acquire(self: &Arc<Self>, endpoint_id: &str) -> Option<EndpointConnectionPermit> {
        let mut counts = self.counts.lock().ok()?;
        let count = counts.entry(endpoint_id.to_string()).or_default();
        if *count >= MAX_CONCURRENT_CONNECTIONS_PER_ENDPOINT {
            return None;
        }
        *count += 1;
        Some(EndpointConnectionPermit {
            quota: Arc::clone(self),
            endpoint_id: endpoint_id.to_string(),
        })
    }
}

struct EndpointConnectionPermit {
    quota: Arc<EndpointConnectionQuota>,
    endpoint_id: String,
}

impl Drop for EndpointConnectionPermit {
    fn drop(&mut self) {
        let Ok(mut counts) = self.quota.counts.lock() else {
            return;
        };
        if let Some(count) = counts.get_mut(&self.endpoint_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.endpoint_id);
            }
        }
    }
}

/// Bind the iroh endpoint with the given identity and ALPN, returning it
/// ready to be passed to [`accept_loop`]. Spawns a background "online" probe
/// that logs when the endpoint reports relay connectivity.
pub async fn bind_endpoint(secret_key: SecretKey) -> anyhow::Result<Endpoint> {
    // iroh defaults already PING every 5s (HEARTBEAT_INTERVAL) which would
    // normally keep the connection alive — but the connection-wide
    // `max_idle_timeout` is still 30s by default, and once the holepunched
    // direct path's per-path 15s timer fires plus the relay path drops, the
    // connection has no live paths left and the 30s idle clock kicks in.
    // Raise the connection-level idle timeout to 10 minutes so phone-side
    // agent tunnels (pi/opencode sitting between thread/list calls) don't
    // get torn down with `connection lost: timed out` while idle. Default
    // path keep-alive (5s) keeps the actual paths alive in normal cases.
    let idle_timeout = IdleTimeout::try_from(Duration::from_secs(600))
        .context("constructing iroh idle timeout")?;
    let transport = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .build();

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![REMORA_LINK_ALPN.to_vec()])
        .transport_config(transport)
        .bind()
        .await
        .context("binding iroh endpoint")?;

    info!("remora endpoint bound");
    let endpoint_for_online = endpoint.clone();
    tokio::spawn(async move {
        if tokio::time::timeout(Duration::from_secs(8), endpoint_for_online.online())
            .await
            .is_ok()
        {
            info!("remora endpoint online");
        } else {
            warn!("remora endpoint did not report relay connectivity within timeout");
        }
    });

    Ok(endpoint)
}

/// Run the iroh accept loop until `shutdown` fires or the endpoint stops
/// yielding incoming connections. Caller owns the [`Endpoint`] and the
/// [`AgentManager`]; both are passed by `Arc`/clone so control-side handlers
/// can keep using them concurrently.
pub async fn accept_loop(
    endpoint: Endpoint,
    agents: AgentManager,
    pairing: PairingManager,
    catalog: Arc<HostCatalogStore>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    let host_endpoint_id = endpoint.id().to_string();
    let connection_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let stream_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS));
    let endpoint_connection_quota = Arc::new(EndpointConnectionQuota::default());
    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("iroh accept loop received shutdown");
                endpoint.close().await;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(connecting) = incoming else {
                    break;
                };
                let Ok(connection_permit) = Arc::clone(&connection_slots).try_acquire_owned() else {
                    warn!("rejecting connection: global connection limit reached");
                    continue;
                };
                let agents = agents.clone();
                let pairing = pairing.clone();
                let catalog = Arc::clone(&catalog);
                let host_endpoint_id = host_endpoint_id.clone();
                let global_stream_slots = Arc::clone(&stream_slots);
                let endpoint_connection_quota = Arc::clone(&endpoint_connection_quota);
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    match connecting.await {
                        Ok(conn) => {
                            let conn_id = conn.stable_id();
                            // `remote_id` is the cryptographic identity we
                            // key sessions on. It's stable across all
                            // bi-streams of this connection.
                            let node_id = conn.remote_id().to_string();
                            let Some(_endpoint_connection_permit) =
                                endpoint_connection_quota.try_acquire(&node_id)
                            else {
                                warn!("rejecting connection: endpoint connection limit reached");
                                conn.close(VarInt::from_u32(0x22), b"connection limit reached");
                                return;
                            };
                            let protocol = conn.alpn().to_vec();
                            let stream_slots = Arc::new(Semaphore::new(
                                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
                            ));
                            info!(
                                conn = conn_id,
                                protocol = "remora-link/2",
                                "iroh connection accepted"
                            );
                            while let Ok((send, recv)) = conn.accept_bi().await {
                                let Ok(global_stream_permit) =
                                    Arc::clone(&global_stream_slots).try_acquire_owned()
                                else {
                                    warn!(conn = conn_id, "closing connection: global stream limit reached");
                                    conn.close(VarInt::from_u32(0x22), b"stream limit reached");
                                    break;
                                };
                                let Ok(stream_permit) =
                                    Arc::clone(&stream_slots).try_acquire_owned()
                                else {
                                    warn!(conn = conn_id, "closing connection: stream limit reached");
                                    conn.close(VarInt::from_u32(0x22), b"stream limit reached");
                                    break;
                                };
                                let agents = agents.clone();
                                let pairing = pairing.clone();
                                let catalog = Arc::clone(&catalog);
                                let host_endpoint_id = host_endpoint_id.clone();
                                let node_id = node_id.clone();
                                let protocol = protocol.clone();
                                let connection = conn.clone();
                                tokio::spawn(async move {
                                    let _global_stream_permit = global_stream_permit;
                                    let _stream_permit = stream_permit;
                                    let result = if protocol == REMORA_LINK_ALPN {
                                        handle_stream_v2(
                                            send,
                                            recv,
                                            agents,
                                            pairing,
                                            catalog,
                                            conn_id,
                                            host_endpoint_id,
                                            node_id,
                                            connection,
                                        )
                                        .await
                                    } else {
                                        Err(anyhow!("unsupported negotiated protocol"))
                                    };
                                    if let Err(error) = result {
                                        info!(conn = conn_id, "remora stream ended: {error:#}");
                                    }
                                });
                            }
                            pairing.unregister_connection_stable_id(conn_id).await;
                            info!(conn = conn_id, "iroh connection closed");
                        }
                        Err(error) => warn!("remora incoming connection failed: {error:#}"),
                    }
                });
            }
        }
    }
    Ok(())
}

// The stream handler receives the authenticated transport identity and live
// connection separately from protocol state; keeping those inputs explicit
// prevents request JSON from becoming an authority source.
#[allow(clippy::too_many_arguments)]
async fn handle_stream_v2(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    agents: AgentManager,
    pairing: PairingManager,
    catalog: Arc<HostCatalogStore>,
    conn: usize,
    host_endpoint_id: String,
    authenticated_client_endpoint_id: String,
    connection: iroh::endpoint::Connection,
) -> anyhow::Result<()> {
    let mut request: RequestV2 = match tokio::time::timeout(
        INITIAL_REQUEST_TIMEOUT,
        read_json_frame_bounded(&mut recv, MAX_REMORA_LINK_V2_FRAME_BYTES),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            // Malformed pre-auth frames are intentionally not echoed back or
            // logged with their contents.
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::error(ErrorCodeV2::InvalidRequest),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            return Err(anyhow!("invalid remora-link/2 request: {error:#}"));
        }
        Err(_) => {
            return Err(anyhow!(
                "timed out waiting for initial remora-link/2 request"
            ));
        }
    };
    if request.version() != PROTOCOL_VERSION_V2 {
        request.zeroize_invitation_secret();
        write_json_frame_bounded(
            &mut send,
            &ResponseV2::error(ErrorCodeV2::InvalidRequest),
            MAX_REMORA_LINK_V2_FRAME_BYTES,
        )
        .await?;
        return Err(anyhow!("invalid remora-link/2 protocol version"));
    }

    let is_pairing = matches!(
        request,
        RequestV2::InspectInvitation { .. } | RequestV2::Enroll { .. }
    );
    let preauth_error = if is_pairing {
        ErrorCodeV2::PairingUnavailable
    } else {
        ErrorCodeV2::AuthorizationRequired
    };
    let challenge = match pairing
        .issue_challenge(&request, &authenticated_client_endpoint_id)
        .await
    {
        Ok(challenge) => challenge,
        Err(_) => {
            request.zeroize_invitation_secret();
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::error(preauth_error),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            return Err(anyhow!(preauth_error.message()));
        }
    };
    write_json_frame_bounded(
        &mut send,
        &ResponseV2::challenge(challenge.clone()),
        MAX_REMORA_LINK_V2_FRAME_BYTES,
    )
    .await?;

    let proof: ProofV2 = match tokio::time::timeout(
        Duration::from_secs(31),
        read_json_frame_bounded(&mut recv, MAX_REMORA_LINK_V2_FRAME_BYTES),
    )
    .await
    {
        Ok(Ok(proof)) => proof,
        _ => {
            request.zeroize_invitation_secret();
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::error(preauth_error),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            return Err(anyhow!(preauth_error.message()));
        }
    };

    match &request {
        RequestV2::InspectInvitation { .. } => {
            let inspection = pairing
                .inspect(
                    &request,
                    &challenge,
                    &proof,
                    &host_endpoint_id,
                    &authenticated_client_endpoint_id,
                )
                .await;
            request.zeroize_invitation_secret();
            let response = match inspection {
                Ok(mut inspection) => {
                    inspection.runtime_offers = runtime_offers_for_grant(
                        agents.list_agents().await,
                        &inspection.max_runtime_ids,
                    );
                    ResponseV2::inspection(inspection)
                }
                Err(_) => ResponseV2::error(ErrorCodeV2::PairingUnavailable),
            };
            write_json_frame_bounded(&mut send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES).await?;
            return if response.ok {
                Ok(())
            } else {
                Err(anyhow!("pairing unavailable"))
            };
        }
        RequestV2::Enroll { .. } => {
            let enrollment = pairing
                .enroll(
                    &request,
                    &challenge,
                    &proof,
                    &host_endpoint_id,
                    &authenticated_client_endpoint_id,
                )
                .await;
            request.zeroize_invitation_secret();
            let response = match enrollment {
                Ok(EnrollmentOutcomeV2::Pending { pending }) => {
                    info!(conn, "remora-link enrollment awaiting host confirmation");
                    ResponseV2::pending(pending)
                }
                Ok(EnrollmentOutcomeV2::Enrolled { enrolled }) => {
                    info!(conn, "remora-link unattended device enrolled");
                    ResponseV2::enrolled(enrolled)
                }
                Err(_) => {
                    warn!(conn, "remora-link enrollment rejected");
                    ResponseV2::error(ErrorCodeV2::PairingUnavailable)
                }
            };
            write_json_frame_bounded(&mut send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES).await?;
            return if response.ok {
                Ok(())
            } else {
                Err(anyhow!("pairing unavailable"))
            };
        }
        RequestV2::RevokeSelf { credential_id, .. } => {
            let credential_id = credential_id.clone();
            let mutation = pairing
                .self_revoke(
                    &request,
                    &challenge,
                    &proof,
                    &host_endpoint_id,
                    &authenticated_client_endpoint_id,
                )
                .await;
            let (applied, response) = revocation_response(mutation);
            if applied {
                pairing
                    .terminate_credential_sessions_except(&credential_id, connection.stable_id())
                    .await;
            }
            let write_result =
                write_json_frame_bounded(&mut send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES)
                    .await;
            if applied {
                let _ = send.finish();
                let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                connection.close(VarInt::from_u32(0x21), b"device revoked");
                pairing
                    .unregister_connection_stable_id(connection.stable_id())
                    .await;
            }
            write_result?;
            return if response.ok {
                Ok(())
            } else {
                Err(anyhow!("device authorization required"))
            };
        }
        RequestV2::RollbackEnrollment { credential_id, .. } => {
            let credential_id = credential_id.clone();
            let mutation = pairing
                .rollback_enrollment(
                    &request,
                    &challenge,
                    &proof,
                    &host_endpoint_id,
                    &authenticated_client_endpoint_id,
                )
                .await;
            let (applied, response) = revocation_response(mutation);
            if applied {
                pairing
                    .terminate_credential_sessions_except(&credential_id, connection.stable_id())
                    .await;
            }
            let write_result =
                write_json_frame_bounded(&mut send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES)
                    .await;
            if applied {
                let _ = send.finish();
                let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                connection.close(VarInt::from_u32(0x21), b"device revoked");
                pairing
                    .unregister_connection_stable_id(connection.stable_id())
                    .await;
            }
            write_result?;
            return if response.ok {
                Ok(())
            } else {
                Err(anyhow!("device authorization required"))
            };
        }
        RequestV2::ListAgents { .. }
        | RequestV2::CommandCenterStatus { .. }
        | RequestV2::PrepareSendMessageIntent { .. }
        | RequestV2::BeginSendMessageIntent { .. }
        | RequestV2::CompleteSendMessageIntent { .. }
        | RequestV2::RestartAgent { .. }
        | RequestV2::Connect { .. } => {}
    }

    let authorization = match pairing
        .authorize_operation(
            &request,
            &challenge,
            &proof,
            &host_endpoint_id,
            &authenticated_client_endpoint_id,
        )
        .await
    {
        Ok(authorization) => authorization,
        Err(_) => {
            warn!(conn, "rejecting remora-link device proof or scope");
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::error(ErrorCodeV2::AuthorizationRequired),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            return Err(anyhow!("device authorization required"));
        }
    };
    if !matches!(request, RequestV2::RestartAgent { .. })
        && !pairing
            .register_authenticated_connection(
                &authorization,
                &authenticated_client_endpoint_id,
                connection.clone(),
            )
            .await
    {
        warn!(
            conn,
            "device authorization changed before session registration"
        );
        write_json_frame_bounded(
            &mut send,
            &ResponseV2::error(ErrorCodeV2::AuthorizationRequired),
            MAX_REMORA_LINK_V2_FRAME_BYTES,
        )
        .await?;
        return Err(anyhow!("device authorization required"));
    }

    match &request {
        RequestV2::InspectInvitation { .. }
        | RequestV2::Enroll { .. }
        | RequestV2::RevokeSelf { .. }
        | RequestV2::RollbackEnrollment { .. } => unreachable!("handled before authorization"),
        RequestV2::ListAgents { .. } => {
            info!(conn, "list_agents");
            let agents = agents_for_grant(
                agents.list_agents().await,
                &authorization.selected_runtime_ids,
            );
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::agents(agents),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            Ok(())
        }
        RequestV2::CommandCenterStatus { .. } => {
            info!(conn, "command_center_status");
            let status = catalog
                .snapshot()
                .command_center_status_for_runtime_ids(&authorization.selected_runtime_ids);
            write_json_frame_bounded(
                &mut send,
                &ResponseV2::command_center_status(status),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            Ok(())
        }
        RequestV2::PrepareSendMessageIntent {
            intent_id,
            thread_id,
            request_fingerprint,
            ..
        } => {
            info!(conn, "prepare_send_message_intent");
            handle_work_intent_mutation(
                &mut send,
                &pairing,
                &catalog,
                &authorization,
                &authenticated_client_endpoint_id,
                thread_id,
                |thread_id| {
                    catalog.prepare_send_message_intent(
                        intent_id,
                        &authorization.credential_id,
                        request_fingerprint,
                        thread_id.clone(),
                        unix_now_ms(),
                    )
                },
            )
            .await
        }
        RequestV2::BeginSendMessageIntent {
            intent_id,
            thread_id,
            request_fingerprint,
            ..
        } => {
            info!(conn, "begin_send_message_intent");
            handle_work_intent_mutation(
                &mut send,
                &pairing,
                &catalog,
                &authorization,
                &authenticated_client_endpoint_id,
                thread_id,
                |thread_id| {
                    catalog.mark_work_intent_dispatching(
                        intent_id,
                        &authorization.credential_id,
                        request_fingerprint,
                        thread_id,
                        unix_now_ms(),
                    )
                },
            )
            .await
        }
        RequestV2::CompleteSendMessageIntent {
            intent_id,
            thread_id,
            request_fingerprint,
            ..
        } => {
            info!(conn, "complete_send_message_intent");
            handle_work_intent_mutation(
                &mut send,
                &pairing,
                &catalog,
                &authorization,
                &authenticated_client_endpoint_id,
                thread_id,
                |thread_id| {
                    catalog.mark_work_intent_succeeded(
                        intent_id,
                        &authorization.credential_id,
                        request_fingerprint,
                        thread_id,
                        unix_now_ms(),
                    )
                },
            )
            .await
        }
        RequestV2::RestartAgent { agent, .. } => {
            info!(conn, %agent, "restart_agent");
            let preparation = match pairing
                .prepare_restart(
                    &request,
                    &authorization,
                    &authenticated_client_endpoint_id,
                    agents.agent_enabled(agent),
                )
                .await
            {
                Ok(preparation) => preparation,
                Err(error) => {
                    let code = if error == RedeemError::AgentUnavailable {
                        ErrorCodeV2::AgentUnavailable
                    } else {
                        ErrorCodeV2::AuthorizationRequired
                    };
                    write_json_frame_bounded(
                        &mut send,
                        &ResponseV2::error(code),
                        MAX_REMORA_LINK_V2_FRAME_BYTES,
                    )
                    .await?;
                    return Err(anyhow!(code.message()));
                }
            };
            let response = match preparation {
                RestartPreparationV2::Succeeded(result)
                | RestartPreparationV2::OutcomeUnknown(result) => ResponseV2::restart(result),
                RestartPreparationV2::Execute(dispatch) => {
                    let result = match tokio::time::timeout(
                        Duration::from_secs(5),
                        agents.restart_agent(dispatch.agent()),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!("restart dispatch timed out")),
                    };
                    if let Err(error) = &result {
                        warn!(conn, %agent, "restart_agent outcome unknown: {error:#}");
                    }
                    match result {
                        Ok(()) => pairing
                            .mark_restart_succeeded(&dispatch)
                            .await
                            .map(ResponseV2::restart)
                            .unwrap_or_else(|_| {
                                ResponseV2::restart(RestartResultV2 {
                                    agent: dispatch.agent().to_string(),
                                    idempotency_key: dispatch.idempotency_key().to_string(),
                                    command_sequence: dispatch.command_sequence(),
                                    status: RestartStatusV2::OutcomeUnknown,
                                })
                            }),
                        Err(_) => ResponseV2::restart(RestartResultV2 {
                            agent: dispatch.agent().to_string(),
                            idempotency_key: dispatch.idempotency_key().to_string(),
                            command_sequence: dispatch.command_sequence(),
                            status: RestartStatusV2::OutcomeUnknown,
                        }),
                    }
                }
            };
            write_json_frame_bounded(&mut send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES).await?;
            if response.ok {
                Ok(())
            } else {
                Err(anyhow!("restart outcome unknown"))
            }
        }
        RequestV2::Connect { agent, resume, .. } => {
            if !agents.agent_enabled(agent) {
                write_json_frame_bounded(
                    &mut send,
                    &ResponseV2::error(ErrorCodeV2::AgentUnavailable),
                    MAX_REMORA_LINK_V2_FRAME_BYTES,
                )
                .await?;
                return Err(anyhow!(
                    "agent disabled, unknown, or authorization revoked: {agent}"
                ));
            }
            let Some(agent_static) = AgentManager::agent_id(agent) else {
                write_json_frame_bounded(
                    &mut send,
                    &ResponseV2::error(ErrorCodeV2::AgentUnavailable),
                    MAX_REMORA_LINK_V2_FRAME_BYTES,
                )
                .await?;
                return Err(anyhow!("unknown agent: {agent}"));
            };
            let connect_start = match pairing
                .prepare_connect_start(&authorization, &authenticated_client_endpoint_id)
                .await
            {
                Ok(permit) => permit,
                Err(_) => {
                    write_json_frame_bounded(
                        &mut send,
                        &ResponseV2::error(ErrorCodeV2::AuthorizationRequired),
                        MAX_REMORA_LINK_V2_FRAME_BYTES,
                    )
                    .await?;
                    return Err(anyhow!("device authorization required"));
                }
            };

            let last_seen = resume.as_ref().map(|resume| resume.last_seq);
            let resolved = agents.session_registry().resolve_attach(
                authorization.credential_id.clone(),
                agent_static,
                last_seen,
            );
            let session_info = SessionInfo {
                attached: resolved.kind.into(),
                current_seq: resolved.current_seq,
                floor_seq: resolved.floor_seq,
            };
            info!(
                conn,
                %agent,
                attached = ?session_info.attached,
                current_seq = session_info.current_seq,
                floor_seq = session_info.floor_seq,
                "connect: dispatching to agent"
            );
            let dispatch_last_seen = match resolved.kind {
                remora_bridge_core::session::AttachKind::Resumed => resolved.effective_last_seen,
                _ => None,
            };
            let setup = run_bounded_connect_setup(
                connect_start,
                REMORA_LINK_CONNECT_SETUP_TIMEOUT,
                async move {
                    write_json_frame_bounded(
                        &mut send,
                        &ResponseV2::session(session_info),
                        MAX_REMORA_LINK_V2_FRAME_BYTES,
                    )
                    .await?;
                    agents
                        .start_agent_with_session(
                            agent,
                            IrohStream::new(send, recv),
                            resolved.session,
                            dispatch_last_seen,
                        )
                        .await
                        .with_context(|| format!("serving agent `{agent}`"))
                },
            )
            .await;
            let started = match setup {
                Ok(result) => result?,
                Err(_) => {
                    warn!(conn, %agent, "connect setup timed out");
                    connection.close(VarInt::from_u32(0x22), b"connect setup timed out");
                    pairing
                        .unregister_connection_stable_id(connection.stable_id())
                        .await;
                    return Err(anyhow!("connect setup timed out"));
                }
            };
            // Setup is irrevocably established and the fence has been released.
            // Revocation can commit and close the connection without waiting
            // for this long-lived runtime stream.
            let result = started.wait().await;
            match &result {
                Ok(()) => info!(conn, %agent, "agent stream finished"),
                Err(error) => warn!(conn, %agent, "agent stream errored: {error:#}"),
            }
            result
        }
    }
}

async fn handle_work_intent_mutation<F>(
    send: &mut iroh::endpoint::SendStream,
    pairing: &PairingManager,
    catalog: &HostCatalogStore,
    authorization: &AuthorizationContextV2,
    authenticated_client_endpoint_id: &str,
    thread_id: &str,
    mutation: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&ThreadId) -> anyhow::Result<WorkIntentPreparation>,
{
    let thread_id = ThreadId(thread_id.to_string());
    let authorized = catalog.snapshot().threads.iter().any(|thread| {
        thread.summary.thread_id == thread_id
            && authorization
                .selected_runtime_ids
                .contains(&thread.summary.runtime_id)
    });
    if !authorized {
        write_json_frame_bounded(
            send,
            &ResponseV2::error(ErrorCodeV2::AuthorizationRequired),
            MAX_REMORA_LINK_V2_FRAME_BYTES,
        )
        .await?;
        return Err(anyhow!(ErrorCodeV2::AuthorizationRequired.message()));
    }
    let operation_fence = match pairing
        .prepare_connect_start(authorization, authenticated_client_endpoint_id)
        .await
    {
        Ok(fence) => fence,
        Err(_) => {
            write_json_frame_bounded(
                send,
                &ResponseV2::error(ErrorCodeV2::AuthorizationRequired),
                MAX_REMORA_LINK_V2_FRAME_BYTES,
            )
            .await?;
            return Err(anyhow!(ErrorCodeV2::AuthorizationRequired.message()));
        }
    };
    let result = mutation(&thread_id);
    drop(operation_fence);
    let response = work_intent_response(result);
    write_json_frame_bounded(send, &response, MAX_REMORA_LINK_V2_FRAME_BYTES).await?;
    if response.ok {
        Ok(())
    } else {
        Err(anyhow!(
            response
                .error_code
                .unwrap_or(ErrorCodeV2::Internal)
                .message()
        ))
    }
}

fn work_intent_response(result: anyhow::Result<WorkIntentPreparation>) -> ResponseV2 {
    match result {
        Ok(preparation) => ResponseV2::work_intent(work_intent_receipt(preparation)),
        Err(_) => ResponseV2::error(ErrorCodeV2::WorkIntentRejected),
    }
}

fn work_intent_receipt(preparation: WorkIntentPreparation) -> WorkIntentReceiptV2 {
    let (record, status) = match preparation {
        WorkIntentPreparation::Execute(record) => (record, WorkIntentStatusV2::Execute),
        WorkIntentPreparation::Reserved(record) => (record, WorkIntentStatusV2::Reserved),
        WorkIntentPreparation::Succeeded(record) => (record, WorkIntentStatusV2::Succeeded),
        WorkIntentPreparation::OutcomeUnknown(record) => {
            (record, WorkIntentStatusV2::OutcomeUnknown)
        }
    };
    WorkIntentReceiptV2 {
        intent_id: record.intent_id,
        thread_id: record
            .thread_id
            .expect("validated send-message intent has a Thread")
            .0,
        turn_id: record.turn_id.map(|turn_id| turn_id.0),
        status,
    }
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn revocation_response(mutation: Result<RevocationMutationV2, RedeemError>) -> (bool, ResponseV2) {
    match mutation {
        Ok(RevocationMutationV2::Durable(receipt)) => (true, ResponseV2::revocation(receipt)),
        Ok(RevocationMutationV2::OutcomeUnknown(receipt)) => {
            (true, ResponseV2::revocation_outcome_unknown(receipt))
        }
        Err(_) => (false, ResponseV2::error(ErrorCodeV2::AuthorizationRequired)),
    }
}

fn agents_for_grant(
    agents: Vec<crate::protocol::AgentInfo>,
    runtime_ids: &[String],
) -> Vec<crate::protocol::AgentInfo> {
    agents
        .into_iter()
        .filter(|agent| runtime_ids.contains(&agent.name))
        .collect()
}

fn runtime_offers_for_grant(
    agents: Vec<crate::protocol::AgentInfo>,
    runtime_ids: &[String],
) -> Vec<crate::pairing_v2::RuntimeOfferV2> {
    agents_for_grant(agents, runtime_ids)
        .into_iter()
        .map(|agent| crate::pairing_v2::RuntimeOfferV2 {
            recommended: agent.name == "codex" && agent.available,
            runtime_id: agent.name,
            display_name: agent.display_name,
            available: agent.available,
        })
        .collect()
}

/// Read the iroh endpoint's currently-known home relay, if any. Pair payloads
/// prefer this over the static config so phones can dial the host even when
/// pkarr/DNS publishing is broken (e.g. IPv6-only relays + Tailscale).
pub fn endpoint_home_relay(endpoint: Option<&Endpoint>) -> Option<String> {
    endpoint?
        .addr()
        .relay_urls()
        .next()
        .map(|url| url.to_string())
}

pub(crate) fn local_host_name() -> Option<String> {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .map(|name| name.trim().trim_end_matches('.').to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AgentInfo, AgentWire};
    use remora_bridge_core::command_center::{
        TurnId, WorkIntentKind, WorkIntentRecord, WorkIntentState,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn agent(name: &str, available: bool) -> AgentInfo {
        AgentInfo {
            name: name.to_string(),
            display_name: name.to_uppercase(),
            wire: AgentWire::Jsonl,
            available,
            presentation: None,
            capabilities: None,
        }
    }

    #[test]
    fn v2_runtime_projection_never_leaks_outside_the_precommitted_grant() {
        let allowed = vec!["codex".to_string()];
        let agents = vec![
            agent("codex", true),
            agent("shell", true),
            agent("claude", false),
        ];

        let listed = agents_for_grant(agents.clone(), &allowed);
        assert_eq!(
            listed
                .iter()
                .map(|agent| agent.name.as_str())
                .collect::<Vec<_>>(),
            ["codex"]
        );

        let offers = runtime_offers_for_grant(agents, &allowed);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].runtime_id, "codex");
        assert!(offers[0].recommended);
    }

    #[test]
    fn endpoint_connection_quota_is_hard_bounded_and_releases_capacity() {
        let quota = Arc::new(EndpointConnectionQuota::default());
        let mut permits = (0..MAX_CONCURRENT_CONNECTIONS_PER_ENDPOINT)
            .map(|_| quota.try_acquire("device-endpoint").expect("within quota"))
            .collect::<Vec<_>>();
        assert!(quota.try_acquire("device-endpoint").is_none());
        assert!(quota.try_acquire("other-endpoint").is_some());

        permits.pop();
        assert!(quota.try_acquire("device-endpoint").is_some());
    }

    #[tokio::test]
    async fn bounded_connect_setup_releases_revocation_fence_when_setup_never_completes() {
        let dropped = Arc::new(AtomicBool::new(false));
        let outcome = run_bounded_connect_setup(
            DropFlag(Arc::clone(&dropped)),
            Duration::from_millis(10),
            std::future::pending::<()>(),
        )
        .await;

        assert!(outcome.is_err());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn committed_unknown_revocation_is_applied_and_returns_correlated_receipt() {
        let receipt = crate::pairing_v2::RevocationReceiptV2 {
            credential_id: "credential-1".to_string(),
            auth_epoch: 2,
            revoked_at: 1_770_000_042,
            idempotency_key: "revoke-operation-1".to_string(),
        };
        let (applied, response) =
            revocation_response(Ok(RevocationMutationV2::OutcomeUnknown(receipt.clone())));

        assert!(applied, "committed state must trigger session termination");
        assert!(!response.ok);
        assert_eq!(response.error_code, Some(ErrorCodeV2::OutcomeUnknown));
        assert_eq!(response.revocation, Some(receipt));

        let (applied, response) = revocation_response(Err(RedeemError::Unavailable));
        assert!(!applied, "a rejected mutation must retain live sessions");
        assert_eq!(
            response.error_code,
            Some(ErrorCodeV2::AuthorizationRequired)
        );
    }

    #[test]
    fn work_intent_receipts_expose_only_opaque_correlation_state() {
        let record = WorkIntentRecord {
            intent_id: "device-intent-1".to_string(),
            origin_credential_id: "abcdefghijklmnopqrstuv".to_string(),
            kind: WorkIntentKind::SendMessage,
            request_fingerprint: "a".repeat(64),
            state: WorkIntentState::Succeeded,
            thread_id: Some(ThreadId("bcdefghijklmnopqrstuvw".to_string())),
            turn_id: Some(TurnId("cdefghijklmnopqrstuvwx".to_string())),
            created_at_ms: 1,
            updated_at_ms: 2,
        };
        let receipt = work_intent_receipt(WorkIntentPreparation::Succeeded(record));
        let response = ResponseV2::work_intent(receipt.clone());
        let value = serde_json::to_value(&response).expect("serialize response");

        assert!(response.ok);
        assert_eq!(response.work_intent, Some(receipt));
        assert!(value.get("prompt").is_none());
        assert!(value.get("request_fingerprint").is_none());
        assert!(value.get("origin_credential_id").is_none());
    }

    #[test]
    fn work_intent_conflicts_do_not_reuse_the_legacy_unsupported_code() {
        let response = work_intent_response(Err(anyhow!("fingerprint mismatch")));

        assert!(!response.ok);
        assert_eq!(response.error_code, Some(ErrorCodeV2::WorkIntentRejected));
        assert_eq!(response.error.as_deref(), Some("work intent rejected"));
        assert!(response.work_intent.is_none());
    }
}
