use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use tokio::{sync::mpsc, time};
use tracing::{error, info, warn};

use crate::{db, ingest, AppState};

pub async fn refresh_dashboard(state: &AppState, broadcast: bool) -> Result<()> {
    let snapshot = ingest::load_dashboard_snapshot(&state.dashboard_path)?;
    let unchanged = {
        let last_fingerprint = state.last_fingerprint.lock().await;
        last_fingerprint.as_deref() == Some(snapshot.fingerprint.as_str())
    };

    if unchanged {
        info!(
            nodes = snapshot.nodes.len(),
            edges = snapshot.edges.len(),
            alerts = snapshot.alerts.len(),
            "dashboard snapshot unchanged"
        );
        return Ok(());
    }

    db::replace_snapshot(&state.pool, &snapshot).await?;

    {
        let mut last_fingerprint = state.last_fingerprint.lock().await;
        if last_fingerprint.as_deref() != Some(snapshot.fingerprint.as_str()) {
            *last_fingerprint = Some(snapshot.fingerprint.clone());
        } else {
            info!(
                nodes = snapshot.nodes.len(),
                edges = snapshot.edges.len(),
                alerts = snapshot.alerts.len(),
                "dashboard snapshot unchanged"
            );
            return Ok(());
        }
    }

    if broadcast {
        let payload = json!({
            "type": "graph_updated",
            "revision": snapshot.fingerprint,
        })
        .to_string();
        let _ = state.broadcaster.send(payload);
    }

    info!(
        nodes = snapshot.nodes.len(),
        edges = snapshot.edges.len(),
        alerts = snapshot.alerts.len(),
        "dashboard snapshot refreshed"
    );

    Ok(())
}

pub fn start_dashboard_watcher(state: AppState) -> Result<()> {
    let path = state.dashboard_path.clone();
    if !path.exists() {
        warn!(dashboard_path = %path.display(), "dashboard watcher not started because path is missing");
        return Ok(());
    }

    let (sender, mut receiver) = mpsc::unbounded_channel();
    let mut watcher = build_watcher(sender)?;
    watcher.watch(&path, RecursiveMode::Recursive)?;

    tokio::spawn(async move {
        let _watcher = watcher;
        run_debounced_refresh(state, path, &mut receiver).await;
    });

    Ok(())
}

fn build_watcher(sender: mpsc::UnboundedSender<()>) -> notify::Result<RecommendedWatcher> {
    notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
        Ok(event) if should_refresh(&event.kind) => {
            let _ = sender.send(());
        }
        Ok(_) => {}
        Err(error) => warn!(error = %error, "dashboard watcher event failed"),
    })
}

async fn run_debounced_refresh(
    state: AppState,
    path: PathBuf,
    receiver: &mut mpsc::UnboundedReceiver<()>,
) {
    info!(dashboard_path = %path.display(), "dashboard watcher started");

    while receiver.recv().await.is_some() {
        time::sleep(Duration::from_millis(600)).await;
        while receiver.try_recv().is_ok() {}

        if let Err(error) = refresh_dashboard(&state, true).await {
            error!(error = %error, "failed to refresh dashboard snapshot");
        }
    }
}

fn should_refresh(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}
