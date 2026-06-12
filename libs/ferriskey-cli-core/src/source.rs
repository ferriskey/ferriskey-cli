use ferriskey_cli_commands::{SourceAddArgs, SourceCommand, SourceRemoveArgs, SourceSubcommand};
use serde::Serialize;
use thiserror::Error;

use crate::config::{ConfigError, FileContextRepository, StoredSource};

type Result<T> = std::result::Result<T, SourceCommandError>;

pub fn run(output_format: &str, command: SourceCommand) -> Result<()> {
    let repository = FileContextRepository::new()?;

    match command.command {
        SourceSubcommand::Add(args) => {
            let name = add(&repository, args)?;
            render_message(output_format, &format!("source '{name}' added"))
        }
        SourceSubcommand::List => {
            let sources = list(&repository)?;
            render_source_list(output_format, &sources)
        }
        SourceSubcommand::Remove(args) => {
            let name = remove(&repository, args)?;
            render_message(output_format, &format!("source '{name}' removed"))
        }
    }
}

/// A source rendered for display, with secrets redacted.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SourceView {
    name: String,
    kind: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    has_secret: bool,
}

#[derive(Debug, Error)]
pub enum SourceCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("source '{0}' does not exist")]
    NotFound(String),
    #[error("unsupported output format: {0}")]
    UnsupportedOutputFormat(String),
    #[error("failed to serialize JSON output")]
    SerializeJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize YAML output")]
    SerializeYaml {
        #[source]
        source: serde_yaml::Error,
    },
}

fn add(repository: &FileContextRepository, args: SourceAddArgs) -> Result<String> {
    let mut store = repository.load()?;
    let name = args.name;
    let source = StoredSource {
        kind: args.kind.as_str().to_owned(),
        url: args.url,
        realm: args.realm,
        client_id: args.client_id,
        client_secret: args.client_secret,
        token: args.token,
        org_id: args.org_id,
    };
    store.sources.insert(name.clone(), source);
    repository.save(&store)?;
    Ok(name)
}

fn list(repository: &FileContextRepository) -> Result<Vec<SourceView>> {
    let store = repository.load()?;
    Ok(store.sources.into_iter().map(to_view).collect())
}

fn remove(repository: &FileContextRepository, args: SourceRemoveArgs) -> Result<String> {
    let mut store = repository.load()?;
    store
        .sources
        .remove(&args.name)
        .ok_or_else(|| SourceCommandError::NotFound(args.name.clone()))?;
    repository.save(&store)?;
    Ok(args.name)
}

fn to_view((name, source): (String, StoredSource)) -> SourceView {
    SourceView {
        name,
        kind: source.kind,
        url: source.url,
        realm: source.realm,
        client_id: source.client_id,
        org_id: source.org_id,
        has_secret: source.client_secret.is_some() || source.token.is_some(),
    }
}

fn render_source_list(output_format: &str, sources: &[SourceView]) -> Result<()> {
    match output_format {
        "table" => {
            let name_width = column_width(sources.iter().map(|s| s.name.len()), "NAME");
            let kind_width = column_width(sources.iter().map(|s| s.kind.len()), "KIND");
            let url_width = column_width(sources.iter().map(|s| s.url.len()), "URL");

            println!(
                "{:<name_width$}  {:<kind_width$}  {:<url_width$}  SECRET",
                "NAME", "KIND", "URL"
            );
            for source in sources {
                println!(
                    "{:<name_width$}  {:<kind_width$}  {:<url_width$}  {}",
                    source.name,
                    source.kind,
                    source.url,
                    if source.has_secret { "yes" } else { "no" }
                );
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(sources)
                    .map_err(|source| SourceCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(sources)
                    .map_err(|source| SourceCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(SourceCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn column_width(lengths: impl Iterator<Item = usize>, header: &str) -> usize {
    lengths.max().unwrap_or(0).max(header.len())
}

fn render_message(output_format: &str, message: &str) -> Result<()> {
    match output_format {
        "table" => {
            println!("{message}");
            Ok(())
        }
        "json" => {
            println!("{}", serde_json::json!({ "message": message }));
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({ "message": message }))
                    .map_err(|source| SourceCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(SourceCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}
