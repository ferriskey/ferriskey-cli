use std::path::Path;

use ferriskey_commands::{
    ContextAddArgs, ContextCommand, ContextRemoveArgs, ContextSubcommand, ContextUseArgs,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::{ConfigError, ContextStore, FileContextRepository, StoredContext};

type Result<T> = std::result::Result<T, ContextCommandError>;

pub fn run(output_format: &str, command: ContextCommand) -> Result<()> {
    let repository = FileContextRepository::new()?;
    let config_path = repository.file_path().to_path_buf();
    let service = ContextService::new(repository);

    match command.command {
        ContextSubcommand::Add(args) => {
            let context = service.add(args)?;
            render_message(output_format, &format!("context '{}' added", context.name))
        }
        ContextSubcommand::List => {
            let contexts = service.list()?;
            render_context_list(output_format, &contexts)
        }
        ContextSubcommand::Path => render_path(output_format, &config_path),
        ContextSubcommand::Use(args) => {
            let context = service.use_context(args)?;
            render_message(
                output_format,
                &format!("active context set to '{}'", context.name),
            )
        }
        ContextSubcommand::Current => {
            let context = service.current()?;
            render_context(output_format, &context)
        }
        ContextSubcommand::Remove(args) => {
            let removed_name = service.remove(args)?;
            render_message(
                output_format,
                &format!("context '{}' removed", removed_name),
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ContextView {
    name: String,
    url: String,
    client_id: String,
    realm: Option<String>,
    is_current: bool,
}

#[derive(Debug, Error)]
pub enum ContextCommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("context '{0}' already exists")]
    AlreadyExists(String),
    #[error("context '{0}' does not exist")]
    NotFound(String),
    #[error("no active context is configured")]
    NoActiveContext,
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

trait ContextRepository {
    fn load(&self) -> Result<ContextStore>;
    fn save(&self, store: &ContextStore) -> Result<()>;
}

impl ContextRepository for FileContextRepository {
    fn load(&self) -> Result<ContextStore> {
        FileContextRepository::load(self).map_err(ContextCommandError::from)
    }

    fn save(&self, store: &ContextStore) -> Result<()> {
        FileContextRepository::save(self, store).map_err(ContextCommandError::from)
    }
}

struct ContextService<R> {
    repository: R,
}

impl<R> ContextService<R>
where
    R: ContextRepository,
{
    fn new(repository: R) -> Self {
        Self { repository }
    }

    fn add(&self, args: ContextAddArgs) -> Result<ContextView> {
        let mut store = self.repository.load()?;
        if store.contexts.contains_key(&args.name) {
            return Err(ContextCommandError::AlreadyExists(args.name));
        }

        let name = args.name;
        let context = StoredContext {
            url: args.url,
            client_id: args.client_id,
            client_secret: args.client_secret,
            realm: args.realm,
        };

        store.contexts.insert(name.clone(), context.clone());
        if store.current_context.is_none() {
            store.current_context = Some(name.clone());
        }
        self.repository.save(&store)?;

        Ok(to_view(&store.current_context, name, context))
    }

    fn list(&self) -> Result<Vec<ContextView>> {
        let store = self.repository.load()?;
        Ok(store
            .contexts
            .into_iter()
            .map(|(name, context)| to_view(&store.current_context, name, context))
            .collect())
    }

    fn use_context(&self, args: ContextUseArgs) -> Result<ContextView> {
        let mut store = self.repository.load()?;
        let context = store
            .contexts
            .get(&args.name)
            .cloned()
            .ok_or_else(|| ContextCommandError::NotFound(args.name.clone()))?;

        store.current_context = Some(args.name.clone());
        self.repository.save(&store)?;

        Ok(to_view(&store.current_context, args.name, context))
    }

    fn current(&self) -> Result<ContextView> {
        let store = self.repository.load()?;
        let current_name = store
            .current_context
            .clone()
            .ok_or(ContextCommandError::NoActiveContext)?;
        let context = store
            .contexts
            .get(&current_name)
            .cloned()
            .ok_or_else(|| ContextCommandError::NotFound(current_name.clone()))?;

        Ok(to_view(&store.current_context, current_name, context))
    }

    fn remove(&self, args: ContextRemoveArgs) -> Result<String> {
        let mut store = self.repository.load()?;
        store
            .contexts
            .remove(&args.name)
            .ok_or_else(|| ContextCommandError::NotFound(args.name.clone()))?;

        if store.current_context.as_deref() == Some(args.name.as_str()) {
            store.current_context = None;
        }

        self.repository.save(&store)?;
        Ok(args.name)
    }
}

fn to_view(current_context: &Option<String>, name: String, context: StoredContext) -> ContextView {
    ContextView {
        is_current: current_context.as_deref() == Some(name.as_str()),
        name,
        url: context.url,
        client_id: context.client_id,
        realm: context.realm,
    }
}

fn render_context_list(output_format: &str, contexts: &[ContextView]) -> Result<()> {
    match output_format {
        "table" => {
            for line in build_context_table_lines(contexts) {
                println!("{line}");
            }
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(contexts)
                    .map_err(|source| ContextCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(contexts)
                    .map_err(|source| ContextCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ContextCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn build_context_table_lines(contexts: &[ContextView]) -> Vec<String> {
    let active_width = contexts
        .iter()
        .map(|context| if context.is_current { 1 } else { 0 })
        .max()
        .unwrap_or(0)
        .max("ACTIVE".len());
    let name_width = contexts
        .iter()
        .map(|context| context.name.len())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let url_width = contexts
        .iter()
        .map(|context| context.url.len())
        .max()
        .unwrap_or(0)
        .max("URL".len());
    let client_id_width = contexts
        .iter()
        .map(|context| context.client_id.len())
        .max()
        .unwrap_or(0)
        .max("CLIENT_ID".len());

    let mut lines = Vec::with_capacity(contexts.len() + 1);
    lines.push(format!(
        "{:<active_width$}  {:<name_width$}  {:<url_width$}  {:<client_id_width$}  REALM",
        "ACTIVE", "NAME", "URL", "CLIENT_ID"
    ));

    for context in contexts {
        lines.push(format!(
            "{:<active_width$}  {:<name_width$}  {:<url_width$}  {:<client_id_width$}  {}",
            if context.is_current { "*" } else { "" },
            context.name,
            context.url,
            context.client_id,
            context.realm.as_deref().unwrap_or("")
        ));
    }

    lines
}

fn render_context(output_format: &str, context: &ContextView) -> Result<()> {
    match output_format {
        "table" => {
            println!("name: {}", context.name);
            println!("url: {}", context.url);
            println!("client_id: {}", context.client_id);
            println!("realm: {}", context.realm.as_deref().unwrap_or(""));
            println!("current: {}", context.is_current);
            Ok(())
        }
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(context)
                    .map_err(|source| ContextCommandError::SerializeJson { source })?
            );
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(context)
                    .map_err(|source| ContextCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ContextCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

fn render_path(output_format: &str, path: &Path) -> Result<()> {
    let path = path.display().to_string();

    match output_format {
        "table" => {
            println!("{path}");
            Ok(())
        }
        "json" => {
            println!("{}", serde_json::json!({ "path": path }));
            Ok(())
        }
        "yaml" => {
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({ "path": path }))
                    .map_err(|source| ContextCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ContextCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
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
                    .map_err(|source| ContextCommandError::SerializeYaml { source })?
            );
            Ok(())
        }
        _ => Err(ContextCommandError::UnsupportedOutputFormat(
            output_format.to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileContextRepository;
    use std::collections::BTreeMap;
    use std::fs;

    #[derive(Default)]
    struct MemoryContextRepository {
        store: std::sync::Mutex<ContextStore>,
    }

    impl MemoryContextRepository {
        fn with_store(store: ContextStore) -> Self {
            Self {
                store: std::sync::Mutex::new(store),
            }
        }
    }

    impl ContextRepository for MemoryContextRepository {
        fn load(&self) -> Result<ContextStore> {
            Ok(self.store.lock().expect("lock").clone())
        }

        fn save(&self, store: &ContextStore) -> Result<()> {
            *self.store.lock().expect("lock") = store.clone();
            Ok(())
        }
    }

    fn add_args(name: &str) -> ContextAddArgs {
        ContextAddArgs {
            name: name.to_owned(),
            url: "https://example.com".to_owned(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
            realm: Some("master".to_owned()),
        }
    }

    #[test]
    fn first_added_context_becomes_current() {
        let service = ContextService::new(MemoryContextRepository::default());

        let created = service.add(add_args("dev")).expect("context created");

        assert!(created.is_current);
        assert_eq!(created.name, "dev");
    }

    #[test]
    fn switching_context_updates_current_flag() {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "dev".to_owned(),
            StoredContext {
                url: "https://dev.example.com".to_owned(),
                client_id: "dev-client".to_owned(),
                client_secret: "secret".to_owned(),
                realm: None,
            },
        );
        contexts.insert(
            "prod".to_owned(),
            StoredContext {
                url: "https://prod.example.com".to_owned(),
                client_id: "prod-client".to_owned(),
                client_secret: "secret".to_owned(),
                realm: None,
            },
        );
        let service = ContextService::new(MemoryContextRepository::with_store(ContextStore {
            current_context: Some("dev".to_owned()),
            contexts,
        }));

        let switched = service
            .use_context(ContextUseArgs {
                name: "prod".to_owned(),
            })
            .expect("context switched");

        assert_eq!(switched.name, "prod");
        assert!(switched.is_current);
    }

    #[test]
    fn duplicate_context_names_are_rejected() {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "dev".to_owned(),
            StoredContext {
                url: "https://example.com".to_owned(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                realm: None,
            },
        );
        let service = ContextService::new(MemoryContextRepository::with_store(ContextStore {
            current_context: Some("dev".to_owned()),
            contexts,
        }));

        let error = service
            .add(add_args("dev"))
            .expect_err("duplicate should fail");

        assert!(matches!(
            error,
            ContextCommandError::AlreadyExists(name) if name == "dev"
        ));
    }

    #[test]
    fn file_repository_round_trips_store() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let repository = FileContextRepository::from_path(temp_dir.path().join("config.toml"));
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "dev".to_owned(),
            StoredContext {
                url: "https://example.com".to_owned(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                realm: Some("master".to_owned()),
            },
        );
        let store = ContextStore {
            current_context: Some("dev".to_owned()),
            contexts,
        };

        repository.save(&store).expect("saved");
        let loaded = repository.load().expect("loaded");

        assert_eq!(loaded, store);
    }

    #[test]
    fn file_repository_writes_expected_toml_shape() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let file_path = temp_dir.path().join("config.toml");
        let repository = FileContextRepository::from_path(file_path.clone());
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "local".to_owned(),
            StoredContext {
                url: "http://localhost:3333".to_owned(),
                client_id: "my-client".to_owned(),
                client_secret: "supersecret".to_owned(),
                realm: Some("master".to_owned()),
            },
        );
        let store = ContextStore {
            current_context: Some("local".to_owned()),
            contexts,
        };

        repository.save(&store).expect("saved");
        let contents = fs::read_to_string(file_path).expect("config contents");

        assert_eq!(
            contents,
            "current-context = \"local\"\n\n[contexts.local]\nurl = \"http://localhost:3333\"\nclient-id = \"my-client\"\nclient-secret = \"supersecret\"\nrealm = \"master\"\n"
        );
    }

    #[test]
    fn table_render_keeps_long_urls_in_their_column() {
        let lines = build_context_table_lines(&[ContextView {
            name: "local".to_owned(),
            url: "http://localhost:3333/realms/master".to_owned(),
            client_id: "cli".to_owned(),
            realm: None,
            is_current: true,
        }]);

        assert_eq!(
            lines[1],
            "*       local  http://localhost:3333/realms/master  cli        "
        );
    }
}
