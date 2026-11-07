//! Test authenticator shared by the integration tests (no optional Poring features needed).

use std::collections::HashMap;
use std::sync::Arc;

use poring::prelude::*;

/// Test authenticator: bearer tokens and `sid` session cookies from a fixed table.
/// `fail` makes it report an unavailable backend.
#[derive(Clone, Default)]
pub struct TableAuth {
    /// token/session -> identity
    pub table: Arc<HashMap<String, Identity>>,
    /// Simulate backend failure.
    pub fail: bool,
}

impl TableAuth {
    /// The standard fixture identities.
    pub fn fixture() -> Self {
        let mut t = HashMap::new();
        t.insert(
            "reader-token".to_owned(),
            Identity::new("alice", Credential::Bearer).with_scopes(["notes:read"]),
        );
        t.insert(
            "writer-token".to_owned(),
            Identity::new("bob", Credential::Bearer).with_scopes(["notes:read", "notes:write"]),
        );
        t.insert(
            "admin-token".to_owned(),
            Identity::new("root", Credential::Bearer)
                .with_scopes(["notes:read", "notes:write"])
                .with_roles(["admin"]),
        );
        t.insert(
            "session-bob".to_owned(),
            Identity::new("bob", Credential::Cookie).with_scopes(["notes:read", "notes:write"]),
        );
        TableAuth {
            table: Arc::new(t),
            fail: false,
        }
    }
}

impl Authenticator for TableAuth {
    const USES_COOKIES: bool = true;

    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        if self.fail {
            return Err(AuthError::Unavailable("table offline".into()));
        }
        if let Some(t) = req.bearer_token() {
            return self
                .table
                .get(t)
                .cloned()
                .map(Some)
                .ok_or(AuthError::Invalid);
        }
        if let Some(sid) = req.cookie("sid") {
            return Ok(self.table.get(sid).cloned());
        }
        Ok(None)
    }
}
