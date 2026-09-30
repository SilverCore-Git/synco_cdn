//! Corps de réponse : octets fixes, vide, ou flux alimenté par une tâche de
//! lecture disque via un canal borné (lecture anticipée limitée).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use tokio::sync::mpsc;

/// Type de corps de toutes les réponses du service.
pub type ResponseBody = BoxBody<Bytes, io::Error>;

pub fn full(bytes: impl Into<Bytes>) -> ResponseBody {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> ResponseBody {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

/// Corps alimenté par un canal. Si l'émetteur s'arrête avant d'avoir envoyé
/// `remaining` octets (erreur disque), le flux se termine par une erreur :
/// hyper coupe alors la connexion (HTTP/1.1) ou le flux (HTTP/2), et le
/// client voit un transfert incomplet qu'il sait réessayer.
#[derive(Debug)]
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    remaining: u64,
}

impl ChannelBody {
    pub fn new(rx: mpsc::Receiver<Result<Bytes, io::Error>>, length: u64) -> Self {
        Self { rx, remaining: length }
    }

    pub fn boxed(self) -> ResponseBody {
        BoxBody::new(self)
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.remaining = this.remaining.saturating_sub(crate::util::to_u64(bytes.len()));
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) if this.remaining > 0 => Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "lecture interrompue avant la fin de la plage",
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
