//! `State<T>`: typed shared state, resolved at compile time.

use crate::ctx::Ctx;
use crate::descriptor::ExtractorKind;
use crate::extract::{ExtractorMeta, FromRequest};

/// Projects a piece of state `Self` out of the app state `S`.
///
/// `#[derive(PoringState)]` on your state struct implements this for every field type.
/// Every type also provides itself. A handler requesting `State<T>` from an app whose
/// state cannot provide `T` fails to compile.
#[diagnostic::on_unimplemented(
    message = "app state `{S}` does not provide `{Self}`",
    label = "`State<{Self}>` is not available in this app",
    note = "add a field of type `{Self}` to the app's state struct and `#[derive(PoringState)]`, or implement `FromRef<{S}>` for `{Self}`"
)]
pub trait FromRef<S> {
    /// Produces `Self` from the app state (typically a cheap clone of an `Arc`).
    fn from_ref(state: &S) -> Self;
}

impl<T: Clone> FromRef<T> for T {
    fn from_ref(state: &T) -> T {
        state.clone()
    }
}

/// Typed state extractor. No runtime type map and no downcasting: the projection is a
/// statically dispatched `FromRef` call.
#[derive(Clone, Copy, Debug, Default)]
pub struct State<T>(pub T);

impl<T> ExtractorMeta for State<T> {
    const KIND: ExtractorKind = ExtractorKind::State;
}

impl<S: Sync, T: FromRef<S> + Send> FromRequest<S> for State<T> {
    type Rejection = std::convert::Infallible;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, std::convert::Infallible> {
        Ok(State(T::from_ref(cx.state)))
    }
}
