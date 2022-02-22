pub use arbitrary;
use once_cell::sync::OnceCell;

#[doc(hidden)]
pub static RUST_LIBFUZZER_DEBUG_PATH: OnceCell<String> = OnceCell::new();

#[doc(hidden)]
#[no_mangle]
pub fn rust_fuzzer_initialize() {
    // Initialize the `RUST_LIBFUZZER_DEBUG_PATH` cell with the path so it can be
    // reused with little overhead.
    if let Ok(path) = std::env::var("RUST_LIBFUZZER_DEBUG_PATH") {
        RUST_LIBFUZZER_DEBUG_PATH
            .set(path)
            .expect("Since this is initialize it is only called once so can never fail");
    }
}

/// Define a fuzz target.
///
/// ## Example
///
/// This example takes a `&[u8]` slice and attempts to parse it. The parsing
/// might fail and return an `Err`, but it shouldn't ever panic or segfault.
///
/// ```no_run
/// #![no_main]
///
/// use libfuzzer_sys::fuzz_target;
///
/// // Note: `|input|` is short for `|input: &[u8]|`.
/// fuzz_target!(|input| {
///     let _result: Result<_, _> = my_crate::parse(input);
/// });
/// # mod my_crate { pub fn parse(_: &[u8]) -> Result<(), ()> { unimplemented!() } }
/// ```
///
/// ## Arbitrary Input Types
///
/// The input is a `&[u8]` slice by default, but you can take arbitrary input
/// types, as long as the type implements [the `arbitrary` crate's `Arbitrary`
/// trait](https://docs.rs/arbitrary/*/arbitrary/trait.Arbitrary.html) (which is
/// also re-exported as `libfuzzer_sys::arbitrary::Arbitrary` for convenience).
///
/// For example, if you wanted to take an arbitrary RGB color, you could do the
/// following:
///
/// ```no_run
/// #![no_main]
/// # mod foo {
///
/// use libfuzzer_sys::{arbitrary::{Arbitrary, Error, Unstructured}, fuzz_target};
///
/// #[derive(Debug)]
/// pub struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// impl<'a> Arbitrary<'a> for Rgb {
///     fn arbitrary(raw: &mut Unstructured<'a>) -> Result<Self, Error> {
///         let mut buf = [0; 3];
///         raw.fill_buffer(&mut buf)?;
///         let r = buf[0];
///         let g = buf[1];
///         let b = buf[2];
///         Ok(Rgb { r, g, b })
///     }
/// }
///
/// // Write a fuzz target that works with RGB colors instead of raw bytes.
/// fuzz_target!(|color: Rgb| {
///     my_crate::convert_color(color);
/// });
/// # mod my_crate {
/// #     use super::Rgb;
/// #     pub fn convert_color(_: Rgb) {}
/// # }
/// # }
/// ```
///
/// You can also enable the `arbitrary` crate's custom derive via this crate's
/// `"arbitrary-derive"` cargo feature.
#[macro_export]
macro_rules! fuzz_target {
    (|$bytes:ident| $body:block) => {
        /// Auto-generated function
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input($bytes: &[u8]) {
            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            // `RUST_LIBFUZZER_DEBUG_PATH` is set in initialization.
            if let Some(path) = $crate::RUST_LIBFUZZER_DEBUG_PATH.get() {
                use std::io::Write;
                let mut file = std::fs::File::create(path)
                    .expect("failed to create `RUST_LIBFUZZER_DEBUG_PATH` file");
                writeln!(&mut file, "{:?}", $bytes)
                    .expect("failed to write to `RUST_LIBFUZZER_DEBUG_PATH` file");
                return;
            }

            $body
        }
    };

    (|$data:ident: &[u8]| $body:block) => {
        $crate::fuzz_target!(|$data| $body);
    };

    (|$data:ident: $dty: ty| $body:block) => {
        /// Auto-generated function
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) {
            use $crate::arbitrary::{Arbitrary, Unstructured};

            // Early exit if we don't have enough bytes for the `Arbitrary`
            // implementation. This helps the fuzzer avoid exploring all the
            // different not-enough-input-bytes paths inside the `Arbitrary`
            // implementation. Additionally, it exits faster, letting the fuzzer
            // get to longer inputs that actually lead to interesting executions
            // quicker.
            if bytes.len() < <$dty as Arbitrary>::size_hint(0).0 {
                return;
            }

            let mut u = Unstructured::new(bytes);
            let data = <$dty as Arbitrary>::arbitrary_take_rest(u);

            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            // `RUST_LIBFUZZER_DEBUG_PATH` is set in initialization.
            if let Some(path) = $crate::RUST_LIBFUZZER_DEBUG_PATH.get() {
                use std::io::Write;
                let mut file = std::fs::File::create(path)
                    .expect("failed to create `RUST_LIBFUZZER_DEBUG_PATH` file");
                (match data {
                    Ok(data) => writeln!(&mut file, "{:#?}", data),
                    Err(err) => writeln!(&mut file, "Arbitrary Error: {}", err),
                })
                .expect("failed to write to `RUST_LIBFUZZER_DEBUG_PATH` file");
                return;
            }

            let $data = match data {
                Ok(d) => d,
                Err(_) => return,
            };

            $body
        }
    };
}
