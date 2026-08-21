use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub dashboard_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr = env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse()
            .context("BIND_ADDR must be a valid socket address")?;

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://ioc_graph:ioc_graph@localhost:5432/ioc_graph".to_string()
        });

        let dashboard_path = env::var("DASHBOARD_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../dashboard"));

        Ok(Self {
            bind_addr,
            database_url,
            dashboard_path,
        })
    }
}
