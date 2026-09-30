//! Métriques au format texte Prometheus (cf. docs/plan/08-exploitation.md#métriques).
//!
//! Tout est en compteurs atomiques : l'enregistrement ne prend aucun verrou
//! et coûte quelques nanosecondes, même sous forte concurrence.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::util::duration_micros;

/// Routes suivies par les métriques et les journaux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Preflight,
    Health,
    UploadOpen,
    UploadPart,
    UploadStatus,
    UploadComplete,
    UploadAbort,
    FileGet,
    InternalReady,
    InternalMetrics,
    InternalRevoke,
    InternalAbort,
    NotFound,
}

impl Route {
    pub const ALL: [Self; 13] = [
        Self::Preflight,
        Self::Health,
        Self::UploadOpen,
        Self::UploadPart,
        Self::UploadStatus,
        Self::UploadComplete,
        Self::UploadAbort,
        Self::FileGet,
        Self::InternalReady,
        Self::InternalMetrics,
        Self::InternalRevoke,
        Self::InternalAbort,
        Self::NotFound,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Health => "health",
            Self::UploadOpen => "upload_open",
            Self::UploadPart => "upload_part",
            Self::UploadStatus => "upload_status",
            Self::UploadComplete => "upload_complete",
            Self::UploadAbort => "upload_abort",
            Self::FileGet => "file_get",
            Self::InternalReady => "internal_ready",
            Self::InternalMetrics => "internal_metrics",
            Self::InternalRevoke => "internal_revoke",
            Self::InternalAbort => "internal_abort",
            Self::NotFound => "not_found",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }
}

const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
const ROUTE_COUNT: usize = Route::ALL.len();

/// Bornes des histogrammes, en secondes.
const BUCKETS_SECS: [f64; 12] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

/// Histogramme à bornes fixes.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; BUCKETS_SECS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    pub fn observe(&self, duration: Duration) {
        let secs = duration.as_secs_f64();
        for (bound, bucket) in BUCKETS_SECS.iter().zip(&self.buckets) {
            if secs <= *bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(duration_micros(duration), Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
        for (bound, bucket) in BUCKETS_SECS.iter().zip(&self.buckets) {
            let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {}", bucket.load(Ordering::Relaxed));
        }
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum_micros.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {count}");
        let _ = writeln!(out, "{name}_sum {}.{:06}", sum / 1_000_000, sum % 1_000_000);
        let _ = writeln!(out, "{name}_count {count}");
    }
}

/// Raisons de refus d'un ticket, pour `cdn_ticket_rejections_total`.
const TICKET_REASONS: [&str; 7] = [
    "ticket_missing",
    "ticket_invalid",
    "ticket_unknown_key",
    "ticket_expired",
    "ticket_revoked",
    "ticket_wrong_operation",
    "ticket_wrong_target",
];

/// Métriques du service.
#[derive(Debug, Default)]
pub struct Metrics {
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    requests: [[AtomicU64; STATUS_CLASSES.len()]; ROUTE_COUNT],
    ticket_rejections: [AtomicU64; TICKET_REASONS.len()],
    pub part_write: Histogram,
    pub range_read: Histogram,
    pub api_callback_failures: AtomicU64,
    pub panics: AtomicU64,
    pub connections_open: AtomicU64,
}

/// Valeurs calculées au moment du rendu (jauges).
#[derive(Debug, Clone, Copy)]
pub struct Gauges {
    pub upload_sessions_open: u64,
    pub buffer_budget_available_bytes: u64,
    pub disk_free_bytes: u64,
}

impl Metrics {
    pub fn record_request(&self, route: Route, status: u16) {
        let class = usize::from(status / 100).saturating_sub(1).min(STATUS_CLASSES.len().saturating_sub(1));
        if let Some(counter) = self.requests.get(route.index()).and_then(|row| row.get(class)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_ticket_rejection(&self, code: &str) {
        if let Some(counter) =
            TICKET_REASONS.iter().position(|reason| *reason == code).and_then(|i| self.ticket_rejections.get(i))
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn add(counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    /// Texte complet exposé sur `/metrics`.
    pub fn render(&self, gauges: Gauges) -> String {
        let mut out = String::with_capacity(8192);
        let counter = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}");
        };
        let gauge = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}");
        };

        counter(
            &mut out,
            "cdn_bytes_received_total",
            "Octets reçus (parts d'envoi).",
            self.bytes_received.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "cdn_bytes_sent_total",
            "Octets envoyés (téléchargements).",
            self.bytes_sent.load(Ordering::Relaxed),
        );

        let _ = writeln!(out, "# HELP cdn_requests_total Requêtes traitées.\n# TYPE cdn_requests_total counter");
        for (route, row) in Route::ALL.iter().zip(&self.requests) {
            for (class, value) in STATUS_CLASSES.iter().zip(row) {
                let value = value.load(Ordering::Relaxed);
                if value > 0 {
                    let _ =
                        writeln!(out, "cdn_requests_total{{route=\"{}\",status=\"{class}\"}} {value}", route.name());
                }
            }
        }

        let _ = writeln!(
            out,
            "# HELP cdn_ticket_rejections_total Tickets refusés.\n# TYPE cdn_ticket_rejections_total counter"
        );
        for (reason, value) in TICKET_REASONS.iter().zip(&self.ticket_rejections) {
            let _ =
                writeln!(out, "cdn_ticket_rejections_total{{reason=\"{reason}\"}} {}", value.load(Ordering::Relaxed));
        }

        self.part_write.render(&mut out, "cdn_part_write_seconds", "Durée de réception et d'écriture d'une part.");
        self.range_read.render(&mut out, "cdn_range_read_seconds", "Durée d'envoi d'une plage d'un fichier.");

        counter(
            &mut out,
            "cdn_api_callback_failures_total",
            "Rappels vers synco_api en échec.",
            self.api_callback_failures.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "cdn_panics_total",
            "Paniques capturées (doit rester à 0).",
            self.panics.load(Ordering::Relaxed),
        );
        gauge(&mut out, "cdn_connections_open", "Connexions ouvertes.", self.connections_open.load(Ordering::Relaxed));
        gauge(&mut out, "cdn_upload_sessions_open", "Sessions d'envoi en mémoire.", gauges.upload_sessions_open);
        gauge(
            &mut out,
            "cdn_buffer_budget_available_bytes",
            "Budget mémoire des tampons disponible.",
            gauges.buffer_budget_available_bytes,
        );
        gauge(&mut out, "cdn_disk_free_bytes", "Espace libre du stockage.", gauges.disk_free_bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_recorded_values() {
        let m = Metrics::default();
        m.record_request(Route::UploadPart, 204);
        m.record_request(Route::UploadPart, 429);
        m.record_request(Route::FileGet, 999);
        m.record_ticket_rejection("ticket_expired");
        m.part_write.observe(Duration::from_millis(30));
        Metrics::add(&m.bytes_received, 4096);
        let text = m.render(Gauges { upload_sessions_open: 2, buffer_budget_available_bytes: 10, disk_free_bytes: 20 });
        assert!(text.contains("cdn_requests_total{route=\"upload_part\",status=\"2xx\"} 1"));
        assert!(text.contains("cdn_requests_total{route=\"upload_part\",status=\"4xx\"} 1"));
        assert!(text.contains("cdn_requests_total{route=\"file_get\",status=\"5xx\"} 1"));
        assert!(text.contains("cdn_ticket_rejections_total{reason=\"ticket_expired\"} 1"));
        assert!(text.contains("cdn_part_write_seconds_bucket{le=\"0.05\"} 1"));
        assert!(text.contains("cdn_part_write_seconds_bucket{le=\"0.025\"} 0"));
        assert!(text.contains("cdn_bytes_received_total 4096"));
        assert!(text.contains("cdn_upload_sessions_open 2"));
    }
}
