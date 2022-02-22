//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::time::Duration;
use std::{env, net::SocketAddr, path::PathBuf};
use structopt::StructOpt;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        PowerQueueCorpusScheduler,
    },
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::tui::TuiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::{I2SRandReplace, Tokens},
        StdMOptMutator,
    },
    observers::{BacktraceObserver, HitcountsMapObserver, MultiMapObserver, TimeObserver},
    stages::{
        calibrate::CalibrationStage,
        power::{PowerMutationalStage, PowerSchedule},
        StdMutationalStage, TracingStage,
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

use libafl_targets::{CmpLogObserver, CMPLOG_MAP, COUNTERS_MAPS};

//#[cfg(target_os = "linux")]
//use libafl_targets::autotokens;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parses a millseconds int into a [`Duration`], used for commandline arg parsing
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "cargo-libafl",
    about = "A `cargo` wrapper to fuzz Rust code with `LibAFL`",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>"
)]
struct Opt {
    #[structopt(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES"
    )]
    cores: Cores,

    #[structopt(
        short = "p",
        long,
        help = "Choose the broker TCP port, otherwise pick one at random",
        name = "PORT"
    )]
    broker_port: Option<u16>,

    #[structopt(
        parse(try_from_str),
        short = "a",
        long,
        help = "Specify a remote broker",
        name = "REMOTE"
    )]
    remote_broker_addr: Option<SocketAddr>,

    #[structopt(
        parse(try_from_str),
        short,
        long,
        help = "Set an initial corpus directory",
        name = "INPUT"
    )]
    input: Vec<PathBuf>,

    #[structopt(
        short,
        long,
        parse(try_from_str),
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[structopt(
        parse(try_from_str = timeout_from_millis_str),
        short,
        long,
        help = "Set the exeucution timeout in milliseconds, default is 1000",
        name = "TIMEOUT",
        default_value = "1000"
    )]
    timeout: Duration,

    #[structopt(
        parse(from_os_str),
        short = "x",
        long,
        help = "Feed the fuzzer with an user-specified list of tokens (often called \"dictionary\")",
        name = "TOKENS",
        multiple = true
    )]
    tokens: Vec<PathBuf>,

    #[structopt(
        long,
        help = "Disable unicode in the UI (for old terminals)",
        name = "DISABLE_UNICODE"
    )]
    disable_unicode: bool,
}

extern "C" {
    // We do not actually cross the FFI bound here.
    #[allow(improper_ctypes)]
    fn rust_fuzzer_test_input(input: &[u8]);

    fn rust_fuzzer_initialize();
}

static mut BACKTRACE: Option<u64> = None;

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub fn main() {
    unsafe {
        rust_fuzzer_initialize();
    }

    let workdir = env::current_dir().unwrap();

    let opt = Opt::from_args();

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

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = TuiMonitor::new(format!("cargo-libafl v{}", VERSION), !opt.disable_unicode);

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr, _core_id| {
        // Create an observation channel using the coverage map
        let edges = unsafe { &mut COUNTERS_MAPS };
        let edges_observer = HitcountsMapObserver::new(MultiMapObserver::new("edges", edges));

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

        // The state of the edges feedback.
        let feedback_state = MapFeedbackState::with_observer(&edges_observer);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let objective = feedback_and_fast!(
            CrashFeedback::new(),
            NewHashFeedback::new_with_observer("NewHashFeedback", &backtrace_observer)
        );

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                tuple_list!(feedback_state),
            )
        });

        // Read tokens
        if state.metadata().get::<Tokens>().is_none() {
            let mut toks = Tokens::default();
            for tokenfile in &token_files {
                toks.add_from_file(tokenfile)?;
            }
            //#[cfg(target_os = "linux")]
            //{
            //    toks += autotokens()?;
            //}

            if !toks.is_empty() {
                state.add_metadata(toks);
            }
        }

        let calibration = CalibrationStage::new(&mut state, &edges_observer);

        // Setup a randomic Input2State stage
        let i2s =
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

        // Setup a MOPT mutator
        let mutator =
            StdMOptMutator::new(&mut state, havoc_mutations().merge(tokens_mutations()), 5)?;

        let power = PowerMutationalStage::new(mutator, PowerSchedule::FAST, &edges_observer);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerCorpusScheduler::new(PowerQueueCorpusScheduler::new());

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

        // Secondary harness due to mut ownership
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe {
                rust_fuzzer_test_input(buf);
            }
            ExitKind::Ok
        };

        // Setup a tracing stage in which we log comparisons
        let tracing = TracingStage::new(InProcessExecutor::new(
            &mut harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?);

        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, tracing, i2s, power);

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            if input_dirs.is_empty() {
                // Generator of printable bytearrays of max size 32
                let mut generator = RandBytesGenerator::new(32);

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
