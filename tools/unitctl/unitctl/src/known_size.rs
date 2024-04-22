use futures::Stream;
use hyper::Body;
use std::io;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

pub enum KnownSize {
    Vec(Vec<u8>),
    Read(Box<dyn Read + Send>, u64),
    String(String),
    Empty,
}

impl KnownSize {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u64 {
        match self {
            KnownSize::Vec(v) => v.len() as u64,
            KnownSize::Read(_, size) => *size,
            KnownSize::String(s) => s.len() as u64,
            KnownSize::Empty => 0,
        }
    }
}

impl Stream for KnownSize {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let buf = &mut [0u8; 1024];

        if let KnownSize::Read(r, _) = self.get_mut() {
            return match r.read(buf) {
                Ok(0) => Poll::Ready(None),
                Ok(n) => Poll::Ready(Some(Ok(buf[..n].to_vec()))),
                Err(e) => Poll::Ready(Some(Err(e))),
            };
        }

        panic!("not implemented")
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.len() as usize))
    }
}

impl From<KnownSize> for Box<dyn Read + Send> {
    fn from(value: KnownSize) -> Self {
        match value {
            KnownSize::Vec(v) => Box::new(Cursor::new(v)),
            KnownSize::Read(r, _) => r,
            KnownSize::String(s) => Box::new(Cursor::new(s)),
            KnownSize::Empty => Box::new(Cursor::new(Vec::new())),
        }
    }
}

impl From<KnownSize> for Body {
    fn from(value: KnownSize) -> Self {
        if value.is_empty() {
            return Body::empty();
        }
        if let KnownSize::Vec(v) = value {
            return Body::from(v);
        }
        if let KnownSize::String(s) = value {
            return Body::from(s);
        }

        Body::wrap_stream(value)
    }
}
