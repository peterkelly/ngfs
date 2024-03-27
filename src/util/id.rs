use std::sync::Arc;
use std::fmt;
use std::cmp::{Ord, Ordering};

#[derive(Clone)]
pub struct Id(Arc<()>);

impl Default for Id {
    fn default() -> Self {
        Id(Arc::new(()))
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Id) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Id {
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Id) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Id) -> Ordering {
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:p}", Arc::as_ptr(&self.0))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:p}", Arc::as_ptr(&self.0))
    }
}
