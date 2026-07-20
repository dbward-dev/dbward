use clap::Parser;

use dbward::output::{self, CliOutcome, ProgressSink, render};

fn main() {
    // try_parse: capture usage errors for JSON-capable error output
    let cli = match dbward::commands::Cli::try_parse() {
        Ok(cli) => cli,
        Err(clap_err) => {
            // --help and --version are not errors — print normally and exit 0
            if clap_err.kind() == clap::error::ErrorKind::DisplayHelp
                || clap_err.kind() == clap::error::ErrorKind::DisplayVersion
            {
                // clap already formatted the output; just print and exit
                print!("{}", clap_err);
                std::process::exit(0);
            }

            let mode = output::detect_format_from_args();
            let outcome: CliOutcome =
                output::CliError::Usage(clap_err.render().to_string()).into();
            render(mode, &outcome);
            std::process::exit(outcome.exit_code);
        }
    };

    if cli.allow_insecure {
        // SAFETY: called before spawning any threads (single-threaded at this point)
        unsafe { std::env::set_var("DBWARD_ALLOW_INSECURE", "true") };
    }

    let mode = cli.format;
    let _progress = ProgressSink::new(mode);

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("BUG: failed to create tokio runtime")
        .block_on(dbward::commands::run(cli));

    match result {
        Ok(Some(outcome)) => {
            // New path: command returned CliOutcome → render it
            render(mode, &outcome);
            std::process::exit(outcome.exit_code);
        }
        Ok(None) => {
            // Legacy path: command already wrote its output directly
        }
        Err(e) => {
            // Convert old CliError to new output system
            let outcome = convert_legacy_error(e);
            render(mode, &outcome);
            std::process::exit(outcome.exit_code);
        }
    }
}

/// Transitional: convert old CliError to CliOutcome for the new render pipeline.
/// This will be removed once all commands return CliResponse<T>.
fn convert_legacy_error(e: dbward::error::CliError) -> CliOutcome {
    use dbward::error::CliError as OldErr;

    let new_err = match &e {
        OldErr::Config(msg) => output::CliError::Config(msg.clone()),
        OldErr::Auth(msg) => output::CliError::Auth(msg.clone()),
        OldErr::Server(msg) => output::CliError::Api {
            code: "server_error".into(),
            message: msg.clone(),
        },
        OldErr::Transport(msg) => output::CliError::Network(msg.clone()),
        OldErr::Io(io_err) => output::CliError::Internal(format!("io: {io_err}")),
        OldErr::Other(msg) => output::CliError::Internal(msg.clone()),
    };

    new_err.into()
}
