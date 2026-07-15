use std::time::Duration;

use base64::Engine as _;
use reqwest::{Method, Response};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{Request, header::AUTHORIZATION};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
enum ClientAuth {
    None,
    /// Compatibility for externally managed legacy test/backends.
    QueryToken(String),
    Basic {
        username: String,
        password: String,
    },
}

#[derive(Clone)]
pub struct OpencodeClient {
    http: reqwest::Client,
    base_url: String,
    auth: ClientAuth,
}

impl OpencodeClient {
    pub fn new(base_url: String, auth_token: String) -> Self {
        let auth = if auth_token.is_empty() {
            ClientAuth::None
        } else {
            ClientAuth::QueryToken(auth_token)
        };
        Self::with_auth(base_url, auth)
    }

    pub(crate) fn new_basic(base_url: String, username: String, password: String) -> Self {
        Self::with_auth(base_url, ClientAuth::Basic { username, password })
    }

    fn with_auth(base_url: String, auth: ClientAuth) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client configuration is valid"),
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.request(Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.request(Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> anyhow::Result<Value> {
        self.request(Method::DELETE, path, None).await
    }

    pub async fn raw_get(&self, path: &str) -> anyhow::Result<Response> {
        let url = self.url(path);
        let req = self.authenticate(self.http.get(url));
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, req.send())
            .await
            .map_err(|_| anyhow::anyhow!("opencode request timed out"))??;
        Ok(resp.error_for_status()?)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut req = self.authenticate(self.http.request(method, self.url(path)));
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, req.send())
            .await
            .map_err(|_| anyhow::anyhow!("opencode request timed out"))??
            .error_for_status()?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        Ok(tokio::time::timeout(REQUEST_TIMEOUT, resp.json())
            .await
            .map_err(|_| anyhow::anyhow!("opencode response body timed out"))??)
    }

    fn url(&self, path: &str) -> String {
        match &self.auth {
            ClientAuth::QueryToken(token) => {
                let sep = if path.contains('?') { '&' } else { '?' };
                format!("{}{}{}auth_token={}", self.base_url, path, sep, token)
            }
            ClientAuth::None | ClientAuth::Basic { .. } => format!("{}{}", self.base_url, path),
        }
    }

    fn authenticate(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            ClientAuth::Basic { username, password } => {
                request.basic_auth(username, Some(password))
            }
            ClientAuth::None | ClientAuth::QueryToken(_) => request,
        }
    }

    /// `ws://…/pty/{id}/connect[?auth_token=…]`. Exposed so `pty.rs` can own
    /// a long-lived websocket per process for the full `command/exec`
    /// lifetime.
    pub fn pty_connect_request(&self, pty_id: &str) -> anyhow::Result<Request<()>> {
        let url = self
            .url(&format!("/pty/{pty_id}/connect"))
            .replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1);
        let mut request = url.into_client_request()?;
        if let ClientAuth::Basic { username, password } = &self.auth {
            let credential =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            request
                .headers_mut()
                .insert(AUTHORIZATION, format!("Basic {credential}").parse()?);
        }
        Ok(request)
    }

    pub async fn pty_create(&self, body: Value) -> anyhow::Result<Value> {
        self.post("/pty", body).await
    }

    pub async fn pty_remove(&self, pty_id: &str) -> anyhow::Result<()> {
        self.delete(&format!("/pty/{pty_id}")).await?;
        Ok(())
    }

    pub async fn pty_resize(&self, pty_id: &str, rows: u32, cols: u32) -> anyhow::Result<()> {
        self.put(
            &format!("/pty/{pty_id}"),
            json!({"size":{"rows":rows,"cols":cols}}),
        )
        .await?;
        Ok(())
    }

    pub async fn put(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.request(Method::PUT, path, Some(body)).await
    }

    pub async fn create_session(
        &self,
        title: Option<String>,
        permission: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut body = serde_json::Map::new();
        if let Some(title) = title {
            body.insert("title".to_string(), json!(title));
        }
        if let Some(permission) = permission {
            body.insert("permission".to_string(), permission);
        }
        self.post("/session", Value::Object(body)).await
    }

    pub async fn summarize_session(
        &self,
        session_id: &str,
        provider_id: &str,
        model_id: &str,
    ) -> anyhow::Result<Value> {
        self.post(
            &format!("/session/{session_id}/summarize"),
            json!({"providerID": provider_id, "modelID": model_id, "auto": false}),
        )
        .await
    }

    pub async fn revert_session(
        &self,
        session_id: &str,
        message_id: &str,
    ) -> anyhow::Result<Value> {
        self.post(
            &format!("/session/{session_id}/revert"),
            json!({"messageID": message_id}),
        )
        .await
    }

    pub async fn fork_session(
        &self,
        session_id: &str,
        message_id: Option<&str>,
    ) -> anyhow::Result<Value> {
        let body = match message_id {
            Some(id) => json!({"messageID": id}),
            None => json!({}),
        };
        self.post(&format!("/session/{session_id}/fork"), body)
            .await
    }

    pub async fn list_messages(&self, session_id: &str) -> anyhow::Result<Value> {
        self.get(&format!("/session/{session_id}/message")).await
    }

    /// `POST /session/:id/prompt_async` — opencode accepts the prompt and
    /// returns 204 immediately; the actual model work is driven over SSE.
    pub async fn prompt_async(&self, session_id: &str, body: Value) -> anyhow::Result<()> {
        self.post(&format!("/session/{session_id}/prompt_async"), body)
            .await?;
        Ok(())
    }

    /// `POST /permission/:requestID/reply` — settle an `asked` permission
    /// prompt. `reply` is one of `"once" | "always" | "reject"` per
    /// `~/dev/opencode/packages/opencode/src/permission/index.ts:Reply`.
    pub async fn permission_reply(
        &self,
        request_id: &str,
        reply: &str,
        message: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut body = json!({"reply": reply});
        if let Some(message) = message {
            body["message"] = json!(message);
        }
        self.post(&format!("/permission/{request_id}/reply"), body)
            .await?;
        Ok(())
    }

    /// `POST /question/:requestID/reply` — settle an `asked` question. `answers`
    /// is `Array<Array<string>>` ordered to match the question array in the
    /// original `Question.Request` (see
    /// `~/dev/opencode/packages/opencode/src/question/index.ts:Reply`).
    pub async fn question_reply(&self, request_id: &str, answers: Value) -> anyhow::Result<()> {
        self.post(
            &format!("/question/{request_id}/reply"),
            json!({"answers": answers}),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_is_a_header_and_never_part_of_the_url() {
        let client = OpencodeClient::new_basic(
            "http://127.0.0.1:4096".into(),
            "opencode".into(),
            "secret-password".into(),
        );
        let request = client.pty_connect_request("pty-1").unwrap();
        assert_eq!(
            request.uri().to_string(),
            "ws://127.0.0.1:4096/pty/pty-1/connect"
        );
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Basic b3BlbmNvZGU6c2VjcmV0LXBhc3N3b3Jk"
        );
        assert!(!request.uri().to_string().contains("secret-password"));
    }
}
