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
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::HasTargetBytes,
    monitors::SimpleMonitor,
    mutators::{
        grimoire::{
            GrimoireExtensionMutator, GrimoireRandomDeleteMutator,
            GrimoireRecursiveReplacementMutator, GrimoireStringReplacementMutator,
        },
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
        StdMOptMutator,
    },
    observers::{BacktraceObserver, HitcountsIterableMapObserver, MultiMapObserver, TimeObserver},
    prelude::{GeneralizedInput, GeneralizedInputBytesGenerator},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, GeneralizationStage, SkippableStage, StdMutationalStage,
        StdPowerMutationalStage, TracingStage,
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

use libafl_targets::{CmpLogObserver, CMPLOG_MAP, COUNTERS_MAPS};

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

    #[arg(short, long, help = "Set an initial corpus directory", name = "INPUT")]
    input: Vec<PathBuf>,

    #[arg(
        short,
        long,
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

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
        name = "GRIMOIRE"
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

    let workdir = env::current_dir().unwrap();

    let opt = Opt::parse();

    let cores = opt.cores;
    let broker_port = opt.broker_port.unwrap_or_else(|| {
        let port = portpicker::pick_unused_port().expect("No ports free");
        println!("Picking the free port {}", port);
        port
    });
    let remote_broker_addr = opt.remote_broker_addr;
    let input_dirs = opt.input;
    let output_dir = opt.output;
    let token_files = opt.tokens;
    let timeout_ms = opt.timeout;
    // let cmplog_enabled = matches.is_present("cmplog");

    if fs::create_dir(&output_dir).is_err() {
        println!("Out dir at {:?} already exists.", &output_dir);
        if !output_dir.is_dir() {
            eprintln!("Out dir at {:?} is not a valid directory!", &output_dir);
            return;
        }
    }
    let crashes_dir = output_dir.join("crashes");
    let corpus_dir = output_dir.join("corpus");

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
    });

    let mut run_client = |state: Option<StdState<_, _, _, _>>, mut mgr, _core_id| {
        // Create an observation channel using the coverage map
        let edges = unsafe { &mut COUNTERS_MAPS };
        let edges_observer =
            HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog = unsafe { &mut CMPLOG_MAP };
        let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

        // Create a stacktrace observer
        let backtrace_observer = BacktraceObserver::new(
            "BacktraceObserver",
            unsafe { &mut BACKTRACE },
            libafl::observers::HarnessType::InProcess,
        );

        // New maximization map feedback linked to the edges observer
        let map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
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
        if state.metadata().get::<Tokens>().is_none() {
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
        let grimoire = StdMutationalStage::new(grimoire_mutator);
        let skippable_grimoire = SkippableStage::new(grimoire, |_s| opt.grimoire.into());

        let power = StdPowerMutationalStage::new(mutator, &edges_observer);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &GeneralizedInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe {
                rust_fuzzer_test_input(buf);
            }
            ExitKind::Ok
        };

        let mut tracing_harness = harness;

        let generalization = GeneralizationStage::new(&edges_observer);

        let skippable_generalization =
            SkippableStage::new(generalization, |_s| opt.grimoire.into());

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

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            if input_dirs.is_empty() {
                // Generator of printable bytearrays of max size 32
                let mut generator =
                    GeneralizedInputBytesGenerator::from(RandBytesGenerator::new(32));

                // Generate 8 initial inputs
                state
                    .generate_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut generator,
                        &mut mgr,
                        8,
                    )
                    .expect("Failed to generate the initial corpus");
                println!(
                    "We imported {} inputs from the generator.",
                    state.corpus().count()
                );
            } else {
                println!("Loading from {:?}", &input_dirs);
                // Load from disk
                state
                    .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dirs)
                    .unwrap_or_else(|_| {
                        panic!("Failed to load initial corpus at {:?}", &input_dirs)
                    });
                println!("We imported {} inputs from disk.", state.corpus().count());
            }
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
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("{:?}", e),
    };
}
