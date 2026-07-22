use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Mutex, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use wasmtime::{Config, Engine, Instance, Module, ResourceLimiter, Store, Trap};

use sovereign_artifact::PreparedInvocation;

use crate::compile_worker::CompileWorker;
use crate::compiled_cache::CompiledCache;
use crate::{ExecutionRuntime, SandboxError};
use sovereign_artifact::Digest;

pub const DEFAULT_ENTRYPOINT: &str = "sovereign_run";

/// The compilation-relevant engine configuration: the wasm feature gates and
/// Cranelift settings that determine how a module is compiled and serialized.
/// Shared verbatim between the in-process engine and the out-of-process
/// compile worker so a worker-serialized module deserializes in the parent.
/// `max_wasm_stack` (a runtime trap threshold, not a compilation setting) is
/// applied by the caller and does not affect serialization compatibility.
pub(crate) fn compile_engine_config() -> Config {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_tail_call(false)
        .wasm_custom_page_sizes(false)
        .wasm_wide_arithmetic(false)
        .wasm_simd(false)
        .wasm_relaxed_simd(false)
        .wasm_multi_memory(false)
        .wasm_memory64(false)
        .wasm_multi_value(false)
        .wasm_extended_const(false)
        .cranelift_nan_canonicalization(true);
    config
}
const WASM_PAGE_BYTES: u128 = 64 * 1024;
const MAX_DEADLINE_TICKS: u64 = 10_000;

/// Host-enforced ceilings. Guest code can request less, never more.
#[derive(Debug, Clone)]
pub struct WasmSandboxLimits {
    pub max_module_bytes: usize,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_wasm_stack_bytes: usize,
    pub fuel: u64,
    pub wall_timeout: Duration,
    pub epoch_tick: Duration,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: 2 * 1024 * 1024,
            max_memory_bytes: 16 * 1024 * 1024,
            max_table_elements: 10_000,
            max_wasm_stack_bytes: 512 * 1024,
            fuel: 1_000_000,
            wall_timeout: Duration::from_millis(250),
            epoch_tick: Duration::from_millis(5),
        }
    }
}

impl WasmSandboxLimits {
    fn validate(&self) -> Result<(), SandboxError> {
        if self.max_module_bytes == 0
            || self.max_memory_bytes == 0
            || self.max_table_elements == 0
            || self.max_wasm_stack_bytes == 0
            || self.fuel == 0
            || self.wall_timeout.is_zero()
            || self.epoch_tick.is_zero()
            || self.epoch_tick > self.wall_timeout
            || deadline_ticks(self.wall_timeout, self.epoch_tick) > MAX_DEADLINE_TICKS
        {
            return Err(SandboxError::InvalidRuntimeLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExecutionResult {
    pub exit_code: i32,
    pub fuel_consumed: u64,
    pub runtime: ExecutionRuntime,
}

#[derive(Debug)]
struct StoreState {
    max_memory_bytes: usize,
    max_table_elements: usize,
    limit_hit: Option<&'static str>,
}

impl ResourceLimiter for StoreState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory_bytes {
            self.limit_hit = Some("linear memory");
            return Err(wasmtime::Error::msg(
                "linear memory request exceeds sandbox ceiling",
            ));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_table_elements {
            self.limit_hit = Some("table elements");
            return Err(wasmtime::Error::msg(
                "table request exceeds sandbox ceiling",
            ));
        }
        Ok(true)
    }

    fn instances(&self) -> usize {
        1
    }

    fn tables(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }
}

/// Default-deny WebAssembly runtime for untrusted, pure-compute modules.
///
/// No imports are linked. A module asking for WASI, filesystem, environment,
/// network, clocks, randomness, or any other host function is rejected before
/// instantiation. Each call receives a fresh Store and instance. This is a
/// Phase A isolation primitive, not a production execution service: artifact
/// compilation still occurs in-process and is not bounded by Store fuel.
#[derive(Debug)]
pub struct WasmSandbox {
    engine: Engine,
    limits: WasmSandboxLimits,
    epoch_stop: SyncSender<()>,
    epoch_worker: Option<JoinHandle<()>>,
    execution_gate: Mutex<()>,
    /// When set, untrusted module compilation is delegated to a killable,
    /// resource-limited child process instead of running in-process. `None`
    /// keeps the Phase A in-process behavior.
    compile_worker: Option<CompileWorker>,
    /// When set, compiled modules are verified-and-loaded from (and, on a
    /// miss, stored to) a signed on-disk cache.
    compiled_cache: Option<CompiledCache>,
}

impl WasmSandbox {
    pub fn new(limits: WasmSandboxLimits) -> Result<Self, SandboxError> {
        limits.validate()?;

        let mut config = compile_engine_config();
        config.max_wasm_stack(limits.max_wasm_stack_bytes);

        let engine = Engine::new(&config)
            .map_err(|error| SandboxError::RuntimeInitialization(error.to_string()))?;
        let (epoch_stop, stop_receiver) = mpsc::sync_channel(1);
        let ticker_engine = engine.clone();
        let epoch_tick = limits.epoch_tick;
        let catch_up_ceiling = deadline_ticks(limits.wall_timeout, limits.epoch_tick);
        let epoch_worker = thread::Builder::new()
            .name("sovereign-wasm-epoch".into())
            .spawn(move || {
                let mut last_tick = Instant::now();
                loop {
                    match stop_receiver.recv_timeout(epoch_tick) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            let now = Instant::now();
                            let elapsed_ticks =
                                elapsed_ticks(last_tick, now, epoch_tick).min(catch_up_ceiling);
                            for _ in 0..elapsed_ticks {
                                ticker_engine.increment_epoch();
                            }
                            last_tick = now;
                        }
                    }
                }
            })
            .map_err(|error| SandboxError::RuntimeInitialization(error.to_string()))?;

        Ok(Self {
            engine,
            limits,
            epoch_stop,
            epoch_worker: Some(epoch_worker),
            execution_gate: Mutex::new(()),
            compile_worker: None,
            compiled_cache: None,
        })
    }

    /// Route untrusted module compilation through a killable, resource-limited
    /// worker process. Without this, compilation runs in-process (Phase A).
    pub fn with_compile_worker(mut self, worker: CompileWorker) -> Self {
        self.compile_worker = Some(worker);
        self
    }

    /// Verify-and-load compiled modules from a signed on-disk cache, storing
    /// on a miss. Without it, every execution compiles from source.
    pub fn with_compiled_cache(mut self, cache: CompiledCache) -> Self {
        self.compiled_cache = Some(cache);
        self
    }

    pub fn execute(&self, module_bytes: &[u8]) -> Result<WasmExecutionResult, SandboxError> {
        self.execute_entrypoint(module_bytes, DEFAULT_ENTRYPOINT)
    }

    /// Crate-private V2 path: the executable can only be sourced from the
    /// immutable artifact owned by a publisher-verified prepared invocation.
    pub(crate) fn execute_verified(
        &self,
        invocation: &PreparedInvocation,
    ) -> Result<WasmExecutionResult, SandboxError> {
        self.execute_entrypoint_with_runtime(
            invocation.artifact().bytes(),
            DEFAULT_ENTRYPOINT,
            ExecutionRuntime::WasmtimeVerifiedPureComputeV2,
        )
    }

    pub fn execute_entrypoint(
        &self,
        module_bytes: &[u8],
        entrypoint: &str,
    ) -> Result<WasmExecutionResult, SandboxError> {
        self.execute_entrypoint_with_runtime(
            module_bytes,
            entrypoint,
            ExecutionRuntime::WasmtimeCorePhaseA,
        )
    }

    fn execute_entrypoint_with_runtime(
        &self,
        module_bytes: &[u8],
        entrypoint: &str,
        runtime: ExecutionRuntime,
    ) -> Result<WasmExecutionResult, SandboxError> {
        if self
            .epoch_worker
            .as_ref()
            .is_none_or(|worker| worker.is_finished())
        {
            return Err(SandboxError::RuntimeUnavailable(
                "epoch deadline worker stopped".into(),
            ));
        }
        let _execution_guard = match self.execution_gate.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(SandboxError::RuntimeBusy),
            Err(TryLockError::Poisoned(_)) => {
                return Err(SandboxError::RuntimeUnavailable(
                    "execution gate poisoned".into(),
                ));
            }
        };

        if module_bytes.len() > self.limits.max_module_bytes {
            return Err(SandboxError::ModuleTooLarge {
                actual: module_bytes.len(),
                maximum: self.limits.max_module_bytes,
            });
        }

        // A verified cache hit skips compilation entirely; a miss compiles
        // (out-of-process when a worker is attached, otherwise in-process) and
        // stores the result under a freshly signed record for next time.
        let component_digest = Digest::of_bytes(module_bytes);
        let cached = self
            .compiled_cache
            .as_ref()
            .and_then(|cache| cache.lookup(&self.engine, component_digest));
        let module = match cached {
            Some(module) => module,
            None => {
                let module = match &self.compile_worker {
                    Some(worker) => worker.compile(&self.engine, module_bytes)?,
                    None => Module::from_binary(&self.engine, module_bytes)
                        .map_err(|error| SandboxError::InvalidModule(error.to_string()))?,
                };
                if let Some(cache) = &self.compiled_cache {
                    if let Ok(serialized) = module.serialize() {
                        let _ = cache.store(component_digest, &serialized);
                    }
                }
                module
            }
        };
        if let Some(import) = module.imports().next() {
            return Err(SandboxError::ForbiddenImport {
                module: import.module().to_string(),
                name: import.name().to_string(),
            });
        }
        self.enforce_static_resource_limits(&module)?;

        let mut store = Store::new(
            &self.engine,
            StoreState {
                max_memory_bytes: self.limits.max_memory_bytes,
                max_table_elements: self.limits.max_table_elements,
                limit_hit: None,
            },
        );
        store.limiter(|state| state);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|error| SandboxError::RuntimeInitialization(error.to_string()))?;
        store.set_epoch_deadline(self.deadline_ticks());
        store.epoch_deadline_trap();

        let instance = match Instance::new(&mut store, &module, &[]) {
            Ok(instance) => instance,
            Err(error) => {
                if let Some(resource) = store.data().limit_hit {
                    return Err(SandboxError::ResourceLimitExceeded(resource.to_string()));
                }
                return Err(map_instantiation_error(error));
            }
        };
        let run = instance
            .get_func(&mut store, entrypoint)
            .ok_or_else(|| SandboxError::MissingEntrypoint(entrypoint.to_string()))?
            .typed::<(), i32>(&store)
            .map_err(|error| SandboxError::InvalidEntrypoint {
                entrypoint: entrypoint.to_string(),
                detail: error.to_string(),
            })?;

        let exit_code = match run.call(&mut store, ()) {
            Ok(exit_code) => exit_code,
            Err(error) => {
                if let Some(resource) = store.data().limit_hit {
                    return Err(SandboxError::ResourceLimitExceeded(resource.to_string()));
                }
                return Err(map_guest_error(error));
            }
        };
        let remaining_fuel = store
            .get_fuel()
            .map_err(|error| SandboxError::ExecutionFailed(error.to_string()))?;

        Ok(WasmExecutionResult {
            exit_code,
            fuel_consumed: self.limits.fuel.saturating_sub(remaining_fuel),
            runtime,
        })
    }

    fn deadline_ticks(&self) -> u64 {
        deadline_ticks(self.limits.wall_timeout, self.limits.epoch_tick)
    }

    fn enforce_static_resource_limits(&self, module: &Module) -> Result<(), SandboxError> {
        let required = module.resources_required();
        if required.num_memories > 1 {
            return Err(SandboxError::ResourceLimitExceeded("memory count".into()));
        }
        if required.num_tables > 1 {
            return Err(SandboxError::ResourceLimitExceeded("table count".into()));
        }
        if required.max_initial_memory_size.is_some_and(|pages| {
            u128::from(pages).saturating_mul(WASM_PAGE_BYTES) > self.limits.max_memory_bytes as u128
        }) {
            return Err(SandboxError::ResourceLimitExceeded("linear memory".into()));
        }
        if required
            .max_initial_table_size
            .is_some_and(|elements| u128::from(elements) > self.limits.max_table_elements as u128)
        {
            return Err(SandboxError::ResourceLimitExceeded("table elements".into()));
        }
        Ok(())
    }
}

impl Drop for WasmSandbox {
    fn drop(&mut self) {
        let _ = self.epoch_stop.try_send(());
        if let Some(worker) = self.epoch_worker.take() {
            let _ = worker.join();
        }
    }
}

fn map_guest_error(error: wasmtime::Error) -> SandboxError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => SandboxError::FuelExhausted,
        Some(Trap::Interrupt) => SandboxError::DeadlineExceeded,
        Some(_) => SandboxError::GuestTrap(error.to_string()),
        None => SandboxError::ExecutionFailed(error.to_string()),
    }
}

fn map_instantiation_error(error: wasmtime::Error) -> SandboxError {
    if error.downcast_ref::<Trap>().is_some() {
        map_guest_error(error)
    } else {
        SandboxError::InstantiationFailed(error.to_string())
    }
}

fn deadline_ticks(wall_timeout: Duration, epoch_tick: Duration) -> u64 {
    let timeout_nanos = wall_timeout.as_nanos();
    let tick_nanos = epoch_tick.as_nanos();
    let ticks = timeout_nanos.saturating_add(tick_nanos - 1) / tick_nanos;
    u64::try_from(ticks.max(1)).unwrap_or(u64::MAX)
}

fn elapsed_ticks(last_tick: Instant, now: Instant, epoch_tick: Duration) -> u64 {
    let ticks = now.duration_since(last_tick).as_nanos() / epoch_tick.as_nanos();
    u64::try_from(ticks.max(1)).unwrap_or(u64::MAX)
}
