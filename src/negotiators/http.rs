//! Plain HTTP negotiation.
//!
//! HTTP proxies accept a normal request directly, so negotiation is a no-op —
//! the negotiator exists only to satisfy the [`NegotiatorTrait`] bound.

use super::NegotiatorTrait;

/// No-op negotiator for plain HTTP proxies.
pub struct HttpNegotiator;

impl NegotiatorTrait for HttpNegotiator {}
