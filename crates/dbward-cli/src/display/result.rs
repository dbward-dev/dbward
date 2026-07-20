/// Result output format for row data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ResultFormat {
    #[default]
    Table,
    Json,
    Csv,
    Vertical,
}

impl From<dbward_config::client::ResultFormatConfig> for ResultFormat {
    fn from(c: dbward_config::client::ResultFormatConfig) -> Self {
        use dbward_config::client::ResultFormatConfig;
        match c {
            ResultFormatConfig::Table => Self::Table,
            ResultFormatConfig::Json => Self::Json,
            ResultFormatConfig::Csv => Self::Csv,
            ResultFormatConfig::Vertical => Self::Vertical,
        }
    }
}
