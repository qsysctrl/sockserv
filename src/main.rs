use sockserv::config::FileConfig;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args().nth(1).map(PathBuf::from);

    let file_config = match &config_path {
        Some(path) => FileConfig::from_file(path)?,
        None => FileConfig::from_str("")?,
    };

    init_logging(&file_config.logging);

    if let Some(path) = &config_path {
        tracing::info!("Loaded configuration from {}", path.display());
    } else {
        tracing::info!("No config file specified, using defaults");
    }

    let (listen_addr, server_config) = file_config.into_server_config();

    sockserv::server::run_with_config(listen_addr, server_config).await?;

    Ok(())
}

fn init_logging(logging: &sockserv::config::LoggingSection) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging.level));

    match logging.format.as_str() {
        "json" => {
            let subscriber = fmt()
                .json()
                .with_env_filter(env_filter)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("failed to set tracing subscriber");
        }
        "full" => {
            let subscriber = fmt()
                .with_env_filter(env_filter)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("failed to set tracing subscriber");
        }
        _ => {
            // "compact" (default)
            let subscriber = fmt()
                .compact()
                .with_env_filter(env_filter)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("failed to set tracing subscriber");
        }
    }
}
