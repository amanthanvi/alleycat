use alleycat_bridge_conformance::{Frame, FrameKind, TargetId, upstream_schema};
use alleycat_codex_proto::WarningNotification;
use serde_json::json;

#[test]
fn local_warning_notification_conforms_to_pinned_codex_schema() {
    if upstream_schema::schema_dir().is_err() {
        return;
    }

    let notification = WarningNotification {
        thread_id: Some("thread-ci".to_string()),
        message: "deterministic schema fixture".to_string(),
    };
    let valid = Frame {
        step: "pinned-schema".to_string(),
        kind: FrameKind::Notification,
        method: "warning".to_string(),
        raw: json!({
            "jsonrpc": "2.0",
            "method": "warning",
            "params": serde_json::to_value(notification).expect("serialize local wire type"),
        }),
    };
    upstream_schema::validate(&valid, TargetId::Codex)
        .expect("local warning notification must match the pinned upstream schema");

    let missing_required_message = Frame {
        raw: json!({
            "jsonrpc": "2.0",
            "method": "warning",
            "params": { "threadId": "thread-ci" },
        }),
        ..valid
    };
    let error = upstream_schema::validate(&missing_required_message, TargetId::Codex)
        .expect_err("the pinned schema must load and reject a missing required field");
    assert!(
        error.contains("message"),
        "unexpected schema error: {error}"
    );
}
