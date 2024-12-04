
use crate::models::Proxy;

pub struct ProxyValidator<I: Iterator> {
    // sender: mpsc::SyncSender<I::Item>,
    // receiver: mpsc::Receiver<I::Item>,
    iterable: I,
}

impl<I: Iterator<Item = Proxy>> ProxyValidator<I> {
    pub fn from(iterable: I) -> Self {
        Self { iterable }
    }

    pub fn iter(&mut self) -> ProxyValidatorIter<I> {
        ProxyValidatorIter { inner: self }
    }
}

pub struct ProxyValidatorIter<'a, I: Iterator> {
    inner: &'a mut ProxyValidator<I>,
}

impl<I: Iterator<Item = Proxy>> Iterator for ProxyValidatorIter<'_, I> {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.iterable.next()
    }
}
