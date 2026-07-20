use serde::Serialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// OutputMode
// ---------------------------------------------------------------------------

/// CLI output mode (global `--format` option).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputMode {
    #[default]
    Human,
    Json,
    Quiet,
}

// ---------------------------------------------------------------------------
// CliResponse<T> — what commands return
// ---------------------------------------------------------------------------

/// Typed response from a command function.
///
/// Commands return `Result<CliResponse<T>, CliError>` where `T: Serialize`.
/// The dispatcher (`run()`) converts this into `CliOutcome` via the `From` impl.
pub struct CliResponse<T: Serialize> {
    /// Output data. None = side-effect command with no data to return.
    pub data: Option<T>,
    /// Warnings (e.g. deprecation notices). Omitted from JSON when empty.
    pub warnings: Vec<String>,
    /// How to display in human mode (stdout/stderr separation).
    pub render: RenderPlan,
    /// Non-zero exit when needed (doctor, audit verify, pending). None = exit 0.
    pub exit_code: Option<i32>,
    /// Machine-readable error info for non-zero exit (JSON envelope `error` field).
    pub error_info: Option<ErrorInfo>,
}

impl<T: Serialize> CliResponse<T> {
    /// Successful response with data and a render plan.
    pub fn ok(data: T, render: RenderPlan) -> Self {
        Self {
            data: Some(data),
            warnings: vec![],
            render,
            exit_code: None,
            error_info: None,
        }
    }

    /// Side-effect command: no data, only a render plan (typically status on stderr).
    pub fn empty(render: RenderPlan) -> Self {
        Self {
            data: None,
            warnings: vec![],
            render,
            exit_code: None,
            error_info: None,
        }
    }

    /// Append a warning message.
    pub fn with_warning(mut self, msg: impl Into<String>) -> Self {
        self.warnings.push(msg.into());
        self
    }

    /// Data-bearing non-zero exit (doctor issues, audit violations, pending approval).
    pub fn with_issues(
        mut self,
        exit_code: i32,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.exit_code = Some(exit_code);
        self.error_info = Some(ErrorInfo {
            code: code.into(),
            message: message.into(),
        });
        self
    }
}

// ---------------------------------------------------------------------------
// RenderPlan — how to display in human mode
// ---------------------------------------------------------------------------

/// Human-mode display plan. Explicitly separates stdout from stderr.
/// JSON renderer ignores this and outputs the `data` field directly.
pub struct RenderPlan {
    /// What goes to stdout (data that can be piped).
    pub stdout: StdoutRender,
    /// Auxiliary info for stderr (status messages, warnings, hints).
    pub stderr: Vec<StderrLine>,
}

impl RenderPlan {
    /// Side-effect command: nothing on stdout, status message on stderr.
    pub fn status(msg: impl Into<String>) -> Self {
        Self {
            stdout: StdoutRender::None,
            stderr: vec![StderrLine::Status(msg.into())],
        }
    }

    /// Table display.
    pub fn table(columns: Vec<Column>, rows: Vec<Vec<String>>) -> Self {
        Self {
            stdout: StdoutRender::Table { columns, rows },
            stderr: vec![],
        }
    }

    /// Raw value with auxiliary info on stderr.
    pub fn raw_with_info(value: String, info: Vec<StderrLine>) -> Self {
        Self {
            stdout: StdoutRender::Raw { value },
            stderr: info,
        }
    }

    /// Empty list: nothing on stdout, "No {entity}." on stderr.
    pub fn empty_list(entity: impl Into<String>) -> Self {
        Self {
            stdout: StdoutRender::None,
            stderr: vec![StderrLine::Status(format!("No {}.", entity.into()))],
        }
    }

    /// Key-value display.
    pub fn key_value(pairs: Vec<(String, String)>) -> Self {
        Self {
            stdout: StdoutRender::KeyValue { pairs },
            stderr: vec![],
        }
    }

    /// Nothing at all (used internally for CliError conversions).
    pub fn none() -> Self {
        Self {
            stdout: StdoutRender::None,
            stderr: vec![],
        }
    }
}

/// What to display on stdout in human mode.
pub enum StdoutRender {
    /// Table (request list, token list, audit list, etc.)
    Table {
        columns: Vec<Column>,
        rows: Vec<Vec<String>>,
    },
    /// Key-Value pairs (whoami, request show, etc.)
    KeyValue { pairs: Vec<(String, String)> },
    /// Raw value (token string, CSV output, etc.)
    Raw { value: String },
    /// Nothing on stdout (side-effect commands).
    None,
}

/// Column definition for table rendering.
pub struct Column {
    pub header: String,
    pub max_width: Option<usize>,
}

impl Column {
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            max_width: None,
        }
    }

    pub fn with_max_width(mut self, width: usize) -> Self {
        self.max_width = Some(width);
        self
    }
}

/// A single line of auxiliary output on stderr.
pub enum StderrLine {
    /// Status message: "Token created successfully."
    Status(String),
    /// Warning: "⚠ --role is deprecated"
    Warn(String),
    /// Hint: "💡 Run `dbward request resume ...`"
    Hint(String),
    /// Key-Value auxiliary info (token create metadata, etc.)
    Info(String, String),
}

// ---------------------------------------------------------------------------
// ErrorInfo — machine-readable error metadata
// ---------------------------------------------------------------------------

/// Machine-readable error info attached to non-zero exit responses.
#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// CliOutcome — type-erased final form for render()
// ---------------------------------------------------------------------------

/// The final type-erased outcome that `render()` consumes.
/// Produced from either `CliResponse<T>` or `CliError`.
pub struct CliOutcome {
    pub ok: bool,
    pub data: Option<Value>,
    pub warnings: Vec<String>,
    pub error: Option<EnvelopeError>,
    pub render: RenderPlan,
    pub exit_code: i32,
}

/// Error section of the JSON envelope.
#[derive(Debug, Clone)]
pub struct EnvelopeError {
    pub code: String,
    pub message: String,
}

impl<T: Serialize> From<CliResponse<T>> for CliOutcome {
    fn from(resp: CliResponse<T>) -> Self {
        let exit_code = resp.exit_code.unwrap_or(0);
        let ok = exit_code == 0;

        // Serialization failure is an implementation bug — panic to surface it.
        let data = resp.data.map(|d| {
            serde_json::to_value(&d).expect("BUG: CliResponse data must be serializable")
        });

        let error = if !ok {
            Some(
                resp.error_info
                    .unwrap_or_else(|| ErrorInfo {
                        code: "unknown".into(),
                        message: "non-zero exit without error info (bug)".into(),
                    }),
            )
            .map(|info| EnvelopeError {
                code: info.code,
                message: info.message,
            })
        } else {
            None
        };

        Self {
            ok,
            data,
            warnings: resp.warnings,
            error,
            render: resp.render,
            exit_code,
        }
    }
}

// ---------------------------------------------------------------------------
// ProgressSink — injected progress output
// ---------------------------------------------------------------------------

/// Progress output abstraction. Created in main, passed to commands.
/// Automatically suppressed in json/quiet modes.
pub struct ProgressSink {
    mode: OutputMode,
}

impl ProgressSink {
    pub fn new(mode: OutputMode) -> Self {
        Self { mode }
    }

    /// Progress message (human: stderr, json/quiet: suppressed).
    pub fn status(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            eprintln!("{msg}");
        }
    }

    /// Warning message (human: stderr with ⚠ prefix, json/quiet: suppressed).
    pub fn warn(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            eprintln!("⚠ {msg}");
        }
    }

    /// Hint message (human: stderr with 💡 prefix, json/quiet: suppressed).
    pub fn hint(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            eprintln!("💡 {msg}");
        }
    }

    /// Returns the current output mode.
    pub fn mode(&self) -> OutputMode {
        self.mode
    }
}
