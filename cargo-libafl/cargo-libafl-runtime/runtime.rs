//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::{self, Parser};
use core::time::Duration;
use std::{env, fs, net::SocketAddr, path::PathBuf};

use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{self, CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{
        grimoire::{
            GrimoireExtensionMutator, GrimoireRandomDeleteMutator,
            GrimoireRecursiveReplacementMutator, GrimoireStringReplacementMutator,
        },
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
        StdMOptMutator,
    },
    observers::{BacktraceObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, logics::IfElseStage, GeneralizationStage, StdMutationalStage,
        StdPowerMutationalStage, TracingStage,
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

use libafl_targets::CmpLogObserver;

#[cfg(feature = "sancov_8bit")]
use libafl::observers::{HitcountsIterableMapObserver, MultiMapObserver};
#[cfg(feature = "sancov_8bit")]
use libafl_targets::COUNTERS_MAPS;

#[cfg(not(feature = "sancov_8bit"))]
use libafl::observers::HitcountsMapObserver;
#[cfg(not(feature = "sancov_8bit"))]
use libafl_targets::coverage::std_edges_map_observer;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_targets::autotokens;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parses a millseconds int into a [`Duration`], used for commandline arg parsing
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Parser, Debug)]
#[command(
    name = "cargo-libafl",
    about = "A `cargo` wrapper to fuzz Rust code with `LibAFL`",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com> and the LibAFL team"
)]
struct Opt {
    #[arg(
        short,
        long,
        value_parser = Cores::from_cmdline,
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        default_value = "1",
        name = "CORES"
    )]
    cores: Cores,

    #[arg(
        short = 'p',
        long,
        help = "Choose the broker TCP port, otherwise pick one at random",
        name = "PORT"
    )]
    broker_port: Option<u16>,

    #[arg(short = 'a', long, help = "Specify a remote broker", name = "REMOTE")]
    remote_broker_addr: Option<SocketAddr>,

    #[arg(short, long, help = "Set seed inputs directory", name = "INPUT")]
    input: Vec<PathBuf>,

    #[arg(short, long, help = "Set the corpus directory", name = "CORPUS")]
    corpus: PathBuf,

    #[arg(short, long, help = "Set the crashes directory", name = "CRASHES")]
    crashes: PathBuf,

    #[arg(short, long, help = "show stdout or redirect to /dev/null")]
    show_stdout: bool,

    #[arg(
        value_parser = timeout_from_millis_str,
        short,
        long,
        help = "Set the execution timeout in milliseconds, default is 1000",
        name = "TIMEOUT",
        default_value = "1000"
    )]
    timeout: Duration,

    #[arg(
        short = 'x',
        long,
        help = "Feed the fuzzer with an user-specified list of tokens (often called \"dictionary\")",
        name = "TOKENS"
    )]
    tokens: Vec<PathBuf>,

    #[arg(
        long,
        help = "Disable unicode in the UI (for old terminals)",
        name = "DISABLE_UNICODE"
    )]
    disable_unicode: bool,

    #[arg(
        short = 'g',
        long,
        help = "Use GRIMOIRE, a mutator for text-based inputs",
        name = "GRIMOIRE",
        default_value_t = false
    )]
    grimoire: bool,
}

extern "C" {
    // We do not actually cross the FFI bound here.
    #[allow(improper_ctypes)]
    fn rust_fuzzer_test_input(input: &[u8]);

    fn rust_fuzzer_initialize();
}

static mut BACKTRACE: Option<u64> = None;

/// The main fn, `no_mangle` as it is a C symbol
#[allow(clippy::too_many_lines)]
#[no_mangle]
pub fn main() {
    unsafe {
        rust_fuzzer_initialize();
    }

    env_logger::init();

    let workdir = env::current_dir().unwrap();

    let opt = Opt::parse();

    let cores = opt.cores;
    let broker_port = opt.broker_port.unwrap_or_else(|| {
        let port = portpicker::pick_unused_port().expect("No ports free");
        log::info!("Picking the free port {}", port);
        port
    });
    let remote_broker_addr = opt.remote_broker_addr;
    let mut input_dirs = opt.input.clone();
    let corpus_dir = opt.corpus;
    let crashes_dir = opt.crashes;
    let token_files = opt.tokens;
    let timeout_ms = opt.timeout;

    for dir in &[&corpus_dir, &crashes_dir] {
        if fs::create_dir(dir).is_err() {
            log::warn!("Out dir at {:?} already exists.", dir);
            if !dir.is_dir() {
                log::error!("Required directory at {:?} is not a valid directory!", dir);
                return;
            }
        }
    }
    log::info!(
        "Workdir: {:?}, Corpus: {:?}, Crashes: {:?}",
        workdir.to_string_lossy().to_string(),
        corpus_dir,
        crashes_dir
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    #[cfg(feature = "tui")]
    let monitor = {
        use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
        let ui = TuiUI::with_version(
            String::from("cargo-libafl"),
            VERSION.to_string(),
            !opt.disable_unicode,
        );
        TuiMonitor::new(ui)
    };
    #[cfg(not(feature = "tui"))]
    let monitor = libafl::monitors::MultiMonitor::new(|s| log::info!("{}", s));

    let mut run_client = |state: Option<StdState<_, _, _, _>>, mut mgr, _core_id| {
        log::debug!("running fuzzing client");
        // first create an observation channel using the coverage map

        #[cfg(feature = "sancov_8bit")]
        let edges_observer = {
            let edges = unsafe { &mut COUNTERS_MAPS };
            // TODO: is the call to edges.clone here the reason for breaking sancov_8bit?
            HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges.clone()))
        };

        #[cfg(not(feature = "sancov_8bit"))]
        let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        // Create a stacktrace observer
        let backtrace_observer = BacktraceObserver::new(
            "BacktraceObserver",
            unsafe { &mut BACKTRACE },
            libafl::observers::HarnessType::InProcess,
        );

        // New maximization map feedback linked to the edges observer
        let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, true);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
            CrashFeedback::new(),
            NewHashFeedback::new(&backtrace_observer)
        );

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                CachedOnDiskCorpus::new(corpus_dir.clone(), 4096).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(crashes_dir.clone()).unwrap(),
                // A reference to the feedbacks, to create their feedback state
                &mut feedback,
                // A reference to the objectives, to create their objective state
                &mut objective,
            )
            .expect("Failed to create state")
        });

        // Read tokens
        if !state.has_metadata::<Tokens>() {
            let mut toks = Tokens::default();
            for tokenfile in &token_files {
                toks.add_from_file(tokenfile)?;
            }
            #[cfg(any(target_os = "linux", target_vendor = "apple"))]
            {
                toks += autotokens()?;
            }

            if !toks.is_empty() {
                state.add_metadata(toks);
            }
        }

        // Setup a randomic Input2State stage
        let i2s =
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

        // Setup a MOPT mutator
        let mutator = StdMOptMutator::new(
            &mut state,
            havoc_mutations().merge(tokens_mutations()),
            7,
            5,
        )?;

        let grimoire_enabled: bool = opt.grimoire.into();
        let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
            tuple_list!(
                GrimoireExtensionMutator::new(),
                GrimoireRecursiveReplacementMutator::new(),
                GrimoireStringReplacementMutator::new(),
                // give more probability to avoid large inputs
                GrimoireRandomDeleteMutator::new(),
                GrimoireRandomDeleteMutator::new(),
            ),
            3,
        );
        let grimoire = StdMutationalStage::transforming(grimoire_mutator);
        let skippable_grimoire = IfElseStage::new(
            |_, _, _, _, _| Ok(grimoire_enabled),
            tuple_list!(grimoire),
            tuple_list!(),
        );
        // SkippableStage::new(grimoire, |_s| opt.grimoire.into());

        let power = StdPowerMutationalStage::new(mutator);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(
            &mut state,
            &edges_observer,
            PowerSchedule::FAST,
        ));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe {
                rust_fuzzer_test_input(buf);
            }
            ExitKind::Ok
        };

        let mut tracing_harness = harness;

        let generalization = GeneralizationStage::new(&edges_observer);
        let skippable_generalization = IfElseStage::new(
            |_, _, _, _, _| Ok(grimoire_enabled),
            tuple_list!(generalization),
            tuple_list!(),
        );

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer, backtrace_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            timeout_ms,
        );

        // Setup a tracing stage in which we log comparisons
        let tracing = TracingStage::new(InProcessExecutor::new(
            &mut tracing_harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?);

        // The order of the stages matter!
        let mut stages = tuple_list!(
            skippable_generalization,
            calibration,
            tracing,
            i2s,
            power,
            skippable_grimoire
        );

        input_dirs.push(corpus_dir.clone());
        log::debug!("Loading initial inputs from {:?}", &input_dirs);
        // Load from disk
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &input_dirs));
        log::debug!("We imported {} inputs from disk.", state.corpus().count());

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            let mut generator = RandBytesGenerator::new(32);

            // Generate 8 initial inputs
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 128)
                .expect("Failed to generate the initial corpus");
            log::debug!(
                "We imported {} inputs from the generator.",
                state.corpus().count()
            );
        }

        log::debug!(
            "Starting fuzz loop with {} inputs in the corpus",
            state.corpus().count()
        );

        if state.corpus().count() == 0 {
            log::error!("Failed to load corpus and/or generate initial inputs.");
            return Err(Error::ShuttingDown);
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        .stdout_file(Some(if opt.show_stdout {
            "/dev/stdout"
        } else {
            "/dev/null"
        }))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("{:?}", e),
    };
}
