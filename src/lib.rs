//! synco_cdn : transport des fichiers chiffrés de bout en bout de Synco.
//!
//! Le service reçoit et sert les morceaux de fichiers déjà chiffrés par le
//! client. Il ne prend aucune décision métier : chaque requête porte un
//! ticket Ed25519 signé par synco_api, vérifié localement. Voir
//! `docs/plan/` pour la conception complète.
//!
//! Organisation :
//! - [`ticket`], [`range`] : analyse des entrées non fiables, sans E/S ;
//! - [`storage`] : sessions d'envoi, écriture positionnelle, lecture ;
//! - [`http`] : écouteurs, routes, CORS ;
//! - [`server`] : assemblage, balayage périodique, arrêt propre.

pub mod api_client;
pub mod body;
pub mod config;
pub mod error;
pub mod http;
pub mod internal_auth;
pub mod limits;
pub mod metrics;
pub mod range;
pub mod revocation;
pub mod server;
pub mod state;
pub mod storage;
pub mod ticket;
pub mod util;

pub use config::Config;
pub use server::Server;
