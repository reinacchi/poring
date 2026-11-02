//! Whole-app compile-time checks, executed by `const` evaluation.
//!
//! `poring_app!` expands to `const _: () = check_app(&APP);`. When a rule is violated,
//! constant evaluation panics and rustc reports `evaluation panicked: poring: ...` with
//! the offending route named. The same rules are mirrored at runtime by
//! [`super::resolve()`], and both are covered by tests.
//!
//! Checks performed here:
//! * duplicate `METHOD path` registrations;
//! * ambiguous paths that differ only in parameter names, and catch-all vs. parameter
//!   conflicts at the same position;
//! * routes whose effective policy requires authentication in an app without an
//!   authenticator;
//! * `Principal<..>` extractors on routes that are not authenticated;
//! * public routes under a strict (`deny_anonymous`) ancestor without a documented
//!   reason, and public routes silently dropping inherited scopes/roles;
//! * routes or groups raising an inherited body limit;
//! * credentialed CORS with a wildcard origin (also rejected earlier by the macro);
//! * principal-keyed rate limits on routes that are not authenticated.

use crate::descriptor::{AppDescriptor, GroupDescriptor, RouteRef};
use crate::policy::{AuthSpec, PolicySpec};

/// Fixed-capacity message buffer usable in `const fn`.
pub struct Msg {
    buf: [u8; 512],
    len: usize,
}

impl Msg {
    /// Starts a message with the `poring: ` prefix.
    pub const fn new() -> Msg {
        Msg {
            buf: [0; 512],
            len: 0,
        }
        .push("poring: ")
    }

    /// Appends a string (truncating at capacity, on a char boundary of ASCII text).
    pub const fn push(mut self, s: &str) -> Msg {
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() && self.len < self.buf.len() {
            self.buf[self.len] = b[i];
            self.len += 1;
            i += 1;
        }
        self
    }

    /// Panics with the message (in const context this becomes a compile error).
    pub const fn fail(self) -> ! {
        let (head, _) = self.buf.split_at(self.len);
        match core::str::from_utf8(head) {
            Ok(s) => panic!("{}", s),
            Err(_) => panic!("poring: policy check failed"),
        }
    }
}

impl Default for Msg {
    fn default() -> Self {
        Msg::new()
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Full path buffer (`prefix + path`, with `/admin` + `/` = `/admin`).
struct PathBuf {
    b: [u8; 512],
    len: usize,
}

const fn full_path(prefix: &str, path: &str) -> PathBuf {
    let mut out = PathBuf {
        b: [0; 512],
        len: 0,
    };
    let p = prefix.as_bytes();
    let mut plen = p.len();
    while plen > 0 && p[plen - 1] == b'/' {
        plen -= 1;
    }
    let mut i = 0;
    while i < plen && out.len < 512 {
        out.b[out.len] = p[i];
        out.len += 1;
        i += 1;
    }
    let r = path.as_bytes();
    if plen > 0 && r.len() == 1 && r[0] == b'/' {
        return out;
    }
    let mut j = 0;
    while j < r.len() && out.len < 512 {
        out.b[out.len] = r[j];
        out.len += 1;
        j += 1;
    }
    out
}

const fn route_full_path(app: &AppDescriptor, r: &RouteRef) -> PathBuf {
    let prefix = match r.group {
        Some(g) => app.groups[g as usize].prefix,
        None => "",
    };
    full_path(prefix, r.desc.path)
}

const fn buf_str(p: &PathBuf) -> &str {
    let (head, _) = p.b.split_at(p.len);
    match core::str::from_utf8(head) {
        Ok(s) => s,
        Err(_) => "<non-utf8 path>",
    }
}

#[derive(Clone, Copy)]
enum SegKind {
    Static,
    Param,
    CatchAll,
}

/// Returns (kind, start, end) of the segment starting at `pos` (pos points after '/').
const fn segment(b: &[u8], len: usize, pos: usize) -> (SegKind, usize, usize) {
    let mut end = pos;
    while end < len && b[end] != b'/' {
        end += 1;
    }
    let kind = if end > pos && b[pos] == b'{' {
        if end > pos + 1 && b[pos + 1] == b'*' {
            SegKind::CatchAll
        } else {
            SegKind::Param
        }
    } else {
        SegKind::Static
    };
    (kind, pos, end)
}

const fn bytes_eq(a: &[u8], a0: usize, a1: usize, b: &[u8], b0: usize, b1: usize) -> bool {
    if a1 - a0 != b1 - b0 {
        return false;
    }
    let mut i = 0;
    while i < a1 - a0 {
        if a[a0 + i] != b[b0 + i] {
            return false;
        }
        i += 1;
    }
    true
}

/// 0 = no conflict, 1 = ambiguous (same shape, different param names), 2 = catch-all vs param.
const fn path_conflict(a: &PathBuf, b: &PathBuf) -> u8 {
    // Both start with '/'.
    let mut pa = 1;
    let mut pb = 1;
    loop {
        let a_done = pa > a.len;
        let b_done = pb > b.len;
        if a_done && b_done {
            return 1;
        }
        if a_done || b_done {
            return 0;
        }
        let (ka, a0, a1) = segment(&a.b, a.len, pa);
        let (kb, b0, b1) = segment(&b.b, b.len, pb);
        match (ka, kb) {
            (SegKind::Static, SegKind::Static) => {
                if !bytes_eq(&a.b, a0, a1, &b.b, b0, b1) {
                    return 0;
                }
            }
            (SegKind::Param, SegKind::Param) => {}
            (SegKind::CatchAll, SegKind::CatchAll) => return 1,
            (SegKind::CatchAll, SegKind::Param) | (SegKind::Param, SegKind::CatchAll) => return 2,
            _ => return 0,
        }
        pa = a1 + 1;
        pb = b1 + 1;
    }
}

const fn group_of<'a>(app: &'a AppDescriptor, r: &RouteRef) -> Option<&'a GroupDescriptor> {
    match r.group {
        Some(g) => Some(&app.groups[g as usize]),
        None => None,
    }
}

const fn describe(m: Msg, app: &AppDescriptor, r: &RouteRef) -> Msg {
    let p = route_full_path(app, r);
    m.push("route `")
        .push(r.desc.method.as_str())
        .push(" ")
        .push(buf_str(&p))
        .push("` (handler `")
        .push(r.desc.name)
        .push("` at ")
        .push(r.desc.file)
        .push(")")
}

/// Effective authentication outcome for one route.
struct EffAuth {
    required: bool,
    public_reason_given: bool,
    strict_ancestor: bool,
    inherited_reqs: bool,
    route_public: bool,
}

const fn eff_auth(
    app: &AppDescriptor,
    group: Option<&GroupDescriptor>,
    route: &PolicySpec,
) -> EffAuth {
    let mut auth = app.defaults.auth;
    let mut strict = app.defaults.strict;
    let mut inherited_reqs = !app.defaults.scopes.is_empty() || !app.defaults.roles.is_empty();
    if let Some(g) = group {
        if !matches!(g.policy.auth, AuthSpec::Inherit) {
            auth = g.policy.auth;
        }
        strict = strict || g.policy.strict;
        inherited_reqs =
            inherited_reqs || !g.policy.scopes.is_empty() || !g.policy.roles.is_empty();
    }
    let route_public = matches!(route.auth, AuthSpec::Public { .. });
    if !matches!(route.auth, AuthSpec::Inherit) {
        auth = route.auth;
    }
    // `strict` on a route constrains nothing (a route has no descendants).
    let (required, reason_given) = match auth {
        AuthSpec::Inherit => (app.has_authenticator, false),
        AuthSpec::Required => (true, false),
        AuthSpec::Public { reason } => (false, !reason.is_empty()),
    };
    EffAuth {
        required,
        public_reason_given: reason_given,
        strict_ancestor: strict,
        inherited_reqs,
        route_public,
    }
}

const fn min_limit(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x < y { x } else { y }),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

const fn u64_str(mut n: u64, buf: &mut [u8; 20]) -> &str {
    let mut i = 20;
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let (_, tail) = buf.split_at(i);
    match core::str::from_utf8(tail) {
        Ok(s) => s,
        Err(_) => "?",
    }
}

/// Whether two canonical route paths conflict under Poring's (matchit-compatible) rules.
/// Exposed for property tests.
#[doc(hidden)]
pub fn paths_conflict(a: &str, b: &str) -> bool {
    let (pa, pb) = (full_path("", a), full_path("", b));
    let same = pa.len == pb.len && bytes_eq(&pa.b, 0, pa.len, &pb.b, 0, pb.len);
    same || path_conflict(&pa, &pb) != 0
}

/// Runs every whole-app check. Intended for `const _: () = check_app(&APP);`.
pub const fn check_app(app: &AppDescriptor) {
    if let Some(c) = &app.cors
        && c.credentials
    {
        let mut i = 0;
        while i < c.origins.len() {
            if str_eq(c.origins[i], "*") {
                Msg::new()
                    .push("app `")
                    .push(app.name)
                    .push("` enables credentialed CORS with wildcard origin `*`; list explicit origins")
                    .fail();
            }
            i += 1;
        }
    }

    let mut gi = 0;
    while gi < app.groups.len() {
        let g = &app.groups[gi];
        if let AuthSpec::Public { reason } = g.policy.auth
            && app.defaults.strict
            && reason.is_empty()
        {
            Msg::new()
                .push("group `")
                .push(g.name)
                .push("` is public under the strict `deny_anonymous` app defaults of `")
                .push(app.name)
                .push("`; declare `public(reason = \"...\")` to document the exception")
                .fail();
        }
        if let (Some(gl), Some(al)) = (g.policy.body_limit, app.defaults.body_limit)
            && gl > al
        {
            Msg::new()
                .push("group `")
                .push(g.name)
                .push("` raises the app body limit; limits may only be narrowed")
                .fail();
        }
        gi += 1;
    }

    let mut i = 0;
    while i < app.routes.len() {
        let r = &app.routes[i];
        let group = group_of(app, r);
        let e = eff_auth(app, group, &r.desc.policy);

        if e.required && !app.has_authenticator {
            describe(Msg::new(), app, r)
                .push(" requires authentication, but app `")
                .push(app.name)
                .push("` declares no authenticator; add `auth: YourAuthenticator` to poring_app!")
                .fail();
        }

        let mut k = 0;
        while k < r.desc.extractors.len() {
            if r.desc.extractors[k].uses_principal && !e.required {
                describe(Msg::new(), app, r)
                    .push(" extracts `")
                    .push(r.desc.extractors[k].ty)
                    .push("` but is not authenticated; declare `policy(auth = required)` or remove the extractor")
                    .fail();
            }
            k += 1;
        }

        let rate = match (r.desc.policy.rate_limit, group) {
            (Some(rl), _) => Some(rl),
            (None, Some(g)) if g.policy.rate_limit.is_some() => g.policy.rate_limit,
            _ => app.defaults.rate_limit,
        };
        if let Some(rl) = rate
            && matches!(rl.key, crate::policy::RateKey::Principal)
            && !e.required
        {
            describe(Msg::new(), app, r)
                .push(" has a principal-keyed rate limit but is not authenticated; key it by IP or require authentication")
                .fail();
        }

        if !e.required && e.strict_ancestor && !e.public_reason_given {
            describe(Msg::new(), app, r)
                .push(" is public under a strict `deny_anonymous` policy; declare `public(reason = \"...\")` to document the exception")
                .fail();
        }
        if e.route_public && e.inherited_reqs && !e.public_reason_given {
            describe(Msg::new(), app, r)
                .push(" is public and would drop inherited scope/role requirements; declare `public(reason = \"...\")` if intended")
                .fail();
        }

        let inherited_limit = match group {
            Some(g) => min_limit(app.defaults.body_limit, g.policy.body_limit),
            None => app.defaults.body_limit,
        };
        if let (Some(rl), Some(il)) = (r.desc.policy.body_limit, inherited_limit)
            && rl > il
        {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            describe(Msg::new(), app, r)
                .push(" declares body_limit ")
                .push(u64_str(rl, &mut b1))
                .push(" bytes, above the inherited limit of ")
                .push(u64_str(il, &mut b2))
                .push(" bytes; limits may only be narrowed")
                .fail();
        }

        let pi = route_full_path(app, r);
        let mut j = i + 1;
        while j < app.routes.len() {
            let o = &app.routes[j];
            let pj = route_full_path(app, o);
            let same = pi.len == pj.len && bytes_eq(&pi.b, 0, pi.len, &pj.b, 0, pj.len);
            if same {
                if r.desc.method.index() == o.desc.method.index() {
                    describe(Msg::new().push("duplicate "), app, r)
                        .push(" is also registered by handler `")
                        .push(o.desc.name)
                        .push("`")
                        .fail();
                }
            } else {
                match path_conflict(&pi, &pj) {
                    1 => {
                        describe(Msg::new().push("ambiguous "), app, r)
                            .push(" and `")
                            .push(buf_str(&pj))
                            .push("` differ only in parameter names; use the same parameter name at the same position")
                            .fail();
                    }
                    2 => {
                        describe(Msg::new().push("conflicting "), app, r)
                            .push(" and `")
                            .push(buf_str(&pj))
                            .push("` put a catch-all and a parameter at the same position")
                            .fail();
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb(s: &str) -> PathBuf {
        full_path("", s)
    }

    #[test]
    fn conflicts_mirror_matchit() {
        // Verify the const checker agrees with matchit on representative shapes.
        let cases = [
            ("/users/{id}", "/users/{name}"),
            ("/users/{id}/a", "/users/{name}/b"),
            ("/users/{id}", "/users/new"),
            ("/files/{*rest}", "/files/{id}"),
            ("/files/{*rest}", "/files/x/{id}"),
            ("/a/{x}", "/a/{x}/"),
            ("/", "/{*rest}"),
            ("/a/{x}/b", "/a/{y}/b"),
        ];
        for (a, b) in cases {
            let mut r = matchit::Router::new();
            r.insert(a, ()).unwrap();
            let matchit_conflict = r.insert(b, ()).is_err();
            let ours = path_conflict(&pb(a), &pb(b)) != 0;
            assert_eq!(ours, matchit_conflict, "{a} vs {b}");
        }
    }

    #[test]
    fn full_path_joining() {
        assert_eq!(buf_str(&full_path("/admin", "/")), "/admin");
        assert_eq!(buf_str(&full_path("/admin/", "/x")), "/admin/x");
        assert_eq!(buf_str(&full_path("", "/x")), "/x");
    }
}
