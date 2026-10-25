use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use crossbeam_queue::SegQueue;

pub const DEFAULT_PAGE_SIZE: usize = 64 * 1024; // 64 KB page

/// Inner raw storage page allocated by MemoryArena
pub struct ArenaPage {
    pub id: usize,
    pub data: Vec<u8>,
    pub ref_count: AtomicUsize,
    pub is_active: AtomicBool,
}

impl ArenaPage {
    pub fn new(id: usize, capacity: usize) -> Self {
        Self {
            id,
            data: vec![0u8; capacity],
            ref_count: AtomicUsize::new(0),
            is_active: AtomicBool::new(false),
        }
    }
}

/// Zero-copy reference-counted slice referencing a pinned memory page in an arena
pub struct ByteSliceRef {
    page: Arc<ArenaPage>,
    pool_return_queue: Arc<SegQueue<Arc<ArenaPage>>>,
    offset: usize,
    len: usize,
}

impl ByteSliceRef {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.page.data[self.offset..self.offset + self.len]
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn page_id(&self) -> usize {
        self.page.id
    }

    #[inline(always)]
    pub fn ref_count(&self) -> usize {
        self.page.ref_count.load(Ordering::Acquire)
    }

    /// Sub-slice without memory copying, retaining parent page reference
    pub fn slice(&self, sub_offset: usize, sub_len: usize) -> Option<ByteSliceRef> {
        if sub_offset + sub_len <= self.len {
            self.page.ref_count.fetch_add(1, Ordering::SeqCst);
            Some(ByteSliceRef {
                page: Arc::clone(&self.page),
                pool_return_queue: Arc::clone(&self.pool_return_queue),
                offset: self.offset + sub_offset,
                len: sub_len,
            })
        } else {
            None
        }
    }
}

impl Clone for ByteSliceRef {
    fn clone(&self) -> Self {
        self.page.ref_count.fetch_add(1, Ordering::SeqCst);
        Self {
            page: Arc::clone(&self.page),
            pool_return_queue: Arc::clone(&self.pool_return_queue),
            offset: self.offset,
            len: self.len,
        }
    }
}

impl Drop for ByteSliceRef {
    fn drop(&mut self) {
        let prev = self.page.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            // Last reference dropped -> return page to arena pool
            self.page.is_active.store(false, Ordering::Release);
            self.pool_return_queue.push(Arc::clone(&self.page));
        }
    }
}

/// Lock-free pre-allocated memory arena managing reusable 64KB pages
pub struct MemoryArena {
    page_size: usize,
    free_queue: Arc<SegQueue<Arc<ArenaPage>>>,
    total_pages_allocated: AtomicUsize,
    total_leases_created: AtomicUsize,
}

impl MemoryArena {
    pub fn new(initial_pages: usize, page_size: usize) -> Self {
        let free_queue = Arc::new(SegQueue::new());
        for i in 0..initial_pages {
            let page = Arc::new(ArenaPage::new(i, page_size));
            free_queue.push(page);
        }

        Self {
            page_size,
            free_queue,
            total_pages_allocated: AtomicUsize::new(initial_pages),
            total_leases_created: AtomicUsize::new(0),
        }
    }

    /// Allocates or recycles an arena page and copies buffer into pinned page, returning ByteSliceRef
    pub fn acquire_slice(&self, data: &[u8]) -> Result<ByteSliceRef, String> {
        if data.len() > self.page_size {
            return Err(format!(
                "Payload size {} exceeds arena page capacity {}",
                data.len(),
                self.page_size
            ));
        }

        let page = match self.free_queue.pop() {
            Some(p) => p,
            None => {
                let id = self.total_pages_allocated.fetch_add(1, Ordering::Relaxed);
                Arc::new(ArenaPage::new(id, self.page_size))
            }
        };

        // Initialize page ref count
        page.ref_count.store(1, Ordering::Release);
        page.is_active.store(true, Ordering::Release);

        // Copy raw payload into page data buffer
        let page_ptr = page.data.as_ptr() as *mut u8;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), page_ptr, data.len());
        }

        self.total_leases_created.fetch_add(1, Ordering::Relaxed);

        Ok(ByteSliceRef {
            page,
            pool_return_queue: Arc::clone(&self.free_queue),
            offset: 0,
            len: data.len(),
        })
    }

    pub fn available_pages(&self) -> usize {
        self.free_queue.len()
    }

    pub fn total_pages(&self) -> usize {
        self.total_pages_allocated.load(Ordering::Relaxed)
    }

    pub fn total_leases(&self) -> usize {
        self.total_leases_created.load(Ordering::Relaxed)
    }
}
