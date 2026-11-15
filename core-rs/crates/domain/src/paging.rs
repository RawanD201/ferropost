//! Pagination shared by list endpoints.

use serde::Serialize;

/// Upper bound on `page_size`. Go accepted any value; an unbounded page size
/// lets a single request scan a whole table.
pub const MAX_PAGE_SIZE: i64 = 1000;

/// `{ "total": n, "list": [...] }`, the shape every Go list endpoint returns.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub total: i64,
    pub list: Vec<T>,
}

/// Normalised `LIMIT`/`OFFSET` derived from 1-based `page` and `page_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub limit: i64,
    pub offset: i64,
}

impl PageRequest {
    /// Matches GoFrame's `Model.Page`: pages below 1 become page 1. The size is
    /// clamped to `1..=MAX_PAGE_SIZE`.
    pub fn new(page: i64, page_size: i64) -> Self {
        let page = page.max(1);
        let limit = page_size.clamp(1, MAX_PAGE_SIZE);
        Self {
            limit,
            offset: (page - 1).saturating_mul(limit),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_page_and_size() {
        assert_eq!(
            PageRequest::new(1, 20),
            PageRequest {
                limit: 20,
                offset: 0
            }
        );
        assert_eq!(
            PageRequest::new(3, 20),
            PageRequest {
                limit: 20,
                offset: 40
            }
        );
        assert_eq!(
            PageRequest::new(0, 20),
            PageRequest {
                limit: 20,
                offset: 0
            }
        );
        assert_eq!(
            PageRequest::new(-5, 0),
            PageRequest {
                limit: 1,
                offset: 0
            }
        );
        assert_eq!(
            PageRequest::new(2, 1_000_000),
            PageRequest {
                limit: MAX_PAGE_SIZE,
                offset: MAX_PAGE_SIZE
            }
        );
    }
}
