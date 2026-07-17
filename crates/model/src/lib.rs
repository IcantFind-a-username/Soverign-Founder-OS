//! Model Gateway: a unified, model-neutral interface with health-aware
//! failover and honest data-disclosure records.
//!
//! Non-negotiables this crate enforces (architecture principles 1, 2, 7):
//!
//! - **Models are replaceable compute components.** The gateway routes one
//!   request through an ordered list of providers; removing or downing the
//!   primary provider does not stop a request as long as any eligible
//!   provider remains. This is the Stage 2 exit criterion.
//! - **Model output is untrusted.** A [`ModelResponse`] is a suggestion. It
//!   carries no authority, holds no keys, and callers must never write it into
//!   authoritative state without independent review. Nothing here touches the
//!   vault, policy, or capability layers.
//! - **Red data never leaves the device.** The gateway refuses to route
//!   Red-classified content to any provider that is not [`ProviderTrust::Local`],
//!   and records what was disclosed to whom.
//!
//! ## Honest limits
//!
//! The providers in this crate are **deterministic local stand-ins, not
//! LLMs.** They exist to prove the routing, health, failover, and disclosure
//! contract without adding a network dependency or a real model. A real
//! cloud provider would implement the same [`ModelProvider`] trait behind an
//! egress broker (which does not exist yet); until it does, only local
//! providers can be marked healthy for Red data. "Cost" and "latency" fields
//! are placeholders a real provider would populate.

use std::fmt;

use serde::Serialize;
use sovereign_contracts::DataClass;

/// Where a provider runs, for confidentiality routing. Local providers run on
/// the founder's device; cloud providers are untrusted for confidentiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrust {
    Local,
    Cloud,
}

/// A provider's self-reported health. `Down` providers are skipped; `Degraded`
/// providers are used only if no `Healthy` provider is eligible first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Degraded,
    Down,
}

/// One request for model assistance. `data_class` drives confidentiality
/// routing; it is the caller's classification of the prompt contents.
#[derive(Debug, Clone)]
pub struct ModelRequest {
    pub task: String,
    pub prompt: String,
    pub data_class: DataClass,
    pub max_output_chars: usize,
}

/// Untrusted model output. It is a suggestion, never authoritative state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelResponse {
    pub text: String,
    pub provider_id: String,
    pub provider_trust: ProviderTrust,
}

/// Non-repudiable record of what a request disclosed to which provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisclosureRecord {
    pub task: String,
    pub provider_id: String,
    pub provider_trust: ProviderTrust,
    pub data_class: DataClass,
    pub provider_index: usize,
    pub output_chars: usize,
    /// Providers that were skipped before this one, and why — an auditable
    /// trail of the failover path taken.
    pub skipped: Vec<SkipReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkipReason {
    pub provider_id: String,
    pub reason: SkipCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipCause {
    /// Red data may not be disclosed to a non-local provider.
    RedDataConfidentiality,
    /// The provider reported itself down.
    Unhealthy,
    /// The provider was tried and returned an error.
    Failed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("no eligible provider could serve the request")]
    AllProvidersFailed,
    #[error("no providers are configured")]
    NoProviders,
    #[error("provider produced output over the requested ceiling")]
    OutputTooLarge,
}

/// A single reason a provider call failed, distinct from routing decisions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("provider failed: {0}")]
pub struct ProviderError(pub String);

/// A model provider. Real cloud providers implement this behind an egress
/// broker; the deterministic providers here implement it locally.
pub trait ModelProvider: Send + Sync {
    fn id(&self) -> &str;
    fn trust(&self) -> ProviderTrust;
    fn health(&self) -> Health;
    fn complete(&self, request: &ModelRequest) -> Result<String, ProviderError>;
}

impl fmt::Debug for dyn ModelProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelProvider")
            .field("id", &self.id())
            .field("trust", &self.trust())
            .field("health", &self.health())
            .finish()
    }
}

/// Ordered, health-aware, confidentiality-respecting model router.
#[derive(Debug, Default)]
pub struct ModelGateway {
    providers: Vec<Box<dyn ModelProvider>>,
}

impl ModelGateway {
    pub fn new(providers: Vec<Box<dyn ModelProvider>>) -> Self {
        Self { providers }
    }

    /// Route one request. Tries providers in order, skipping any that are
    /// confidentiality-ineligible or down, then any healthy provider, then
    /// (only if no healthy one served it) degraded providers. Returns the
    /// first successful response with a disclosure record of the path taken.
    pub fn complete(
        &self,
        request: &ModelRequest,
    ) -> Result<(ModelResponse, DisclosureRecord), ModelError> {
        if self.providers.is_empty() {
            return Err(ModelError::NoProviders);
        }
        // Two passes: prefer Healthy providers, then fall back to Degraded.
        // Down and confidentiality-ineligible providers are never used.
        let mut skipped = Vec::new();
        for allow_degraded in [false, true] {
            for (index, provider) in self.providers.iter().enumerate() {
                let eligible = self.classify(provider.as_ref(), request, allow_degraded);
                match eligible {
                    Eligibility::Skip(cause) => {
                        // Record each distinct skip once (on the pass that
                        // first rejects it) to keep the trail readable.
                        if !allow_degraded || cause != SkipCause::Unhealthy {
                            record_skip(&mut skipped, provider.id(), cause);
                        }
                        continue;
                    }
                    Eligibility::Try => match provider.complete(request) {
                        Ok(text) => {
                            if text.chars().count() > request.max_output_chars {
                                return Err(ModelError::OutputTooLarge);
                            }
                            let disclosure = DisclosureRecord {
                                task: request.task.clone(),
                                provider_id: provider.id().to_owned(),
                                provider_trust: provider.trust(),
                                data_class: request.data_class,
                                provider_index: index,
                                output_chars: text.chars().count(),
                                skipped: skipped.clone(),
                            };
                            return Ok((
                                ModelResponse {
                                    text,
                                    provider_id: provider.id().to_owned(),
                                    provider_trust: provider.trust(),
                                },
                                disclosure,
                            ));
                        }
                        Err(_) => {
                            record_skip(&mut skipped, provider.id(), SkipCause::Failed);
                            continue;
                        }
                    },
                }
            }
        }
        Err(ModelError::AllProvidersFailed)
    }

    fn classify(
        &self,
        provider: &dyn ModelProvider,
        request: &ModelRequest,
        allow_degraded: bool,
    ) -> Eligibility {
        // Red data may only be disclosed to local providers, regardless of
        // health. This check comes first: confidentiality is not negotiable.
        if request.data_class == DataClass::Red && provider.trust() != ProviderTrust::Local {
            return Eligibility::Skip(SkipCause::RedDataConfidentiality);
        }
        match provider.health() {
            Health::Healthy => Eligibility::Try,
            Health::Degraded if allow_degraded => Eligibility::Try,
            Health::Degraded | Health::Down => Eligibility::Skip(SkipCause::Unhealthy),
        }
    }

    pub fn provider_ids(&self) -> Vec<&str> {
        self.providers
            .iter()
            .map(|provider| provider.id())
            .collect()
    }
}

enum Eligibility {
    Try,
    Skip(SkipCause),
}

fn record_skip(skipped: &mut Vec<SkipReason>, provider_id: &str, reason: SkipCause) {
    if !skipped.iter().any(|entry| entry.provider_id == provider_id) {
        skipped.push(SkipReason {
            provider_id: provider_id.to_owned(),
            reason,
        });
    }
}

/// A deterministic local provider for tests and demos. It is **not an LLM**:
/// it produces fixed, inspectable text so the gateway contract is provable
/// without a network or a model. Health is settable to exercise failover.
pub struct DeterministicProvider {
    id: String,
    trust: ProviderTrust,
    health: Health,
    /// If true, `complete` returns an error, to exercise the failed-then-fail-
    /// over path distinctly from a Down provider.
    fail_on_call: bool,
    template: fn(&ModelRequest, &str) -> String,
}

impl fmt::Debug for DeterministicProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicProvider")
            .field("id", &self.id)
            .field("trust", &self.trust)
            .field("health", &self.health)
            .field("fail_on_call", &self.fail_on_call)
            .finish()
    }
}

impl DeterministicProvider {
    pub fn local(id: impl Into<String>, health: Health) -> Self {
        Self {
            id: id.into(),
            trust: ProviderTrust::Local,
            health,
            fail_on_call: false,
            template: default_template,
        }
    }

    /// A local provider that returns the request prompt verbatim. Used when
    /// the caller has already composed the draft deterministically and wants
    /// the gateway only for resilient routing and disclosure recording.
    pub fn local_echo(id: impl Into<String>, health: Health) -> Self {
        Self {
            id: id.into(),
            trust: ProviderTrust::Local,
            health,
            fail_on_call: false,
            template: echo_template,
        }
    }

    pub fn cloud(id: impl Into<String>, health: Health) -> Self {
        Self {
            id: id.into(),
            trust: ProviderTrust::Cloud,
            health,
            fail_on_call: false,
            template: default_template,
        }
    }

    pub fn failing(mut self) -> Self {
        self.fail_on_call = true;
        self
    }
}

fn echo_template(request: &ModelRequest, _provider_id: &str) -> String {
    request.prompt.clone()
}

fn default_template(request: &ModelRequest, provider_id: &str) -> String {
    format!(
        "[draft suggestion · {task} · via {provider_id}]\n{prompt}",
        task = request.task,
        provider_id = provider_id,
        prompt = request.prompt,
    )
}

impl ModelProvider for DeterministicProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn trust(&self) -> ProviderTrust {
        self.trust
    }

    fn health(&self) -> Health {
        self.health
    }

    fn complete(&self, request: &ModelRequest) -> Result<String, ProviderError> {
        if self.fail_on_call {
            return Err(ProviderError(format!("{} simulated failure", self.id)));
        }
        Ok((self.template)(request, &self.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(data_class: DataClass) -> ModelRequest {
        ModelRequest {
            task: "draft_outreach".into(),
            prompt: "Say hello to Dr. Tan".into(),
            data_class,
            max_output_chars: 4096,
        }
    }

    #[test]
    fn primary_serves_when_healthy() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local(
                "local-primary",
                Health::Healthy,
            )),
            Box::new(DeterministicProvider::local(
                "local-backup",
                Health::Healthy,
            )),
        ]);
        let (response, disclosure) = gateway.complete(&request(DataClass::Amber)).unwrap();
        assert_eq!(response.provider_id, "local-primary");
        assert!(disclosure.skipped.is_empty());
    }

    #[test]
    fn removing_primary_does_not_stop_the_workflow() {
        // Stage 2 exit criterion: primary down → backup serves the request.
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local("primary", Health::Down)),
            Box::new(DeterministicProvider::cloud(
                "cloud-backup",
                Health::Healthy,
            )),
            Box::new(DeterministicProvider::local(
                "local-fallback",
                Health::Healthy,
            )),
        ]);
        let (response, disclosure) = gateway.complete(&request(DataClass::Green)).unwrap();
        assert_eq!(response.provider_id, "cloud-backup");
        assert_eq!(disclosure.provider_index, 1);
        assert_eq!(disclosure.skipped[0].provider_id, "primary");
        assert_eq!(disclosure.skipped[0].reason, SkipCause::Unhealthy);
    }

    #[test]
    fn failed_call_fails_over_to_next_provider() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local("flaky", Health::Healthy).failing()),
            Box::new(DeterministicProvider::local("stable", Health::Healthy)),
        ]);
        let (response, disclosure) = gateway.complete(&request(DataClass::Green)).unwrap();
        assert_eq!(response.provider_id, "stable");
        assert_eq!(disclosure.skipped[0].reason, SkipCause::Failed);
    }

    #[test]
    fn degraded_used_only_after_healthy_exhausted() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local("degraded", Health::Degraded)),
            Box::new(DeterministicProvider::local("healthy", Health::Healthy)),
        ]);
        // Healthy wins on the first pass even though degraded is listed first.
        let (response, _) = gateway.complete(&request(DataClass::Green)).unwrap();
        assert_eq!(response.provider_id, "healthy");

        // With only a degraded provider, the second pass uses it.
        let degraded_only = ModelGateway::new(vec![Box::new(DeterministicProvider::local(
            "degraded",
            Health::Degraded,
        ))]);
        let (response, _) = degraded_only.complete(&request(DataClass::Green)).unwrap();
        assert_eq!(response.provider_id, "degraded");
    }

    #[test]
    fn red_data_never_reaches_a_cloud_provider() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::cloud("cloud", Health::Healthy)),
            Box::new(DeterministicProvider::local("local", Health::Healthy)),
        ]);
        let (response, disclosure) = gateway.complete(&request(DataClass::Red)).unwrap();
        assert_eq!(response.provider_id, "local");
        assert_eq!(response.provider_trust, ProviderTrust::Local);
        assert_eq!(
            disclosure.skipped[0].reason,
            SkipCause::RedDataConfidentiality
        );
    }

    #[test]
    fn red_data_with_only_cloud_providers_fails_closed() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::cloud("cloud-a", Health::Healthy)),
            Box::new(DeterministicProvider::cloud("cloud-b", Health::Healthy)),
        ]);
        // Red data cannot be served by any cloud provider: fail rather than leak.
        assert_eq!(
            gateway.complete(&request(DataClass::Red)),
            Err(ModelError::AllProvidersFailed)
        );
    }

    #[test]
    fn all_down_fails_closed() {
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local("a", Health::Down)),
            Box::new(DeterministicProvider::local("b", Health::Down)),
        ]);
        assert_eq!(
            gateway.complete(&request(DataClass::Green)),
            Err(ModelError::AllProvidersFailed)
        );
    }

    #[test]
    fn no_providers_is_an_explicit_error() {
        let gateway = ModelGateway::default();
        assert_eq!(
            gateway.complete(&request(DataClass::Green)),
            Err(ModelError::NoProviders)
        );
    }
}
