use std::{
    collections::HashMap,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::BindingCoreError;

#[derive(Debug, Clone, Copy)]
pub enum EvictionPolicy {
    LruLowestKey,
    RejectFull { registry_name: &'static str },
}

#[derive(Debug)]
pub struct Registry<T: Clone> {
    inner: RwLock<HashMap<u64, T>>,
    next_key: AtomicU64,
    capacity: usize,
    policy: EvictionPolicy,
}

impl<T: Clone> Registry<T> {
    pub fn new(capacity: usize, policy: EvictionPolicy) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            next_key: AtomicU64::new(1),
            capacity,
            policy,
        }
    }

    pub fn insert(&self, value: T) -> Result<u64, BindingCoreError> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        match self.policy {
            EvictionPolicy::LruLowestKey => {
                while inner.len() >= self.capacity {
                    let Some(lowest_key) = inner.keys().min().copied() else {
                        break;
                    };
                    inner.remove(&lowest_key);
                }
            }
            EvictionPolicy::RejectFull { registry_name } if inner.len() >= self.capacity => {
                return Err(BindingCoreError::RegistryFull {
                    registry: registry_name,
                    capacity: self.capacity,
                });
            }
            EvictionPolicy::RejectFull { .. } => {}
        }

        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        inner.insert(key, value);
        Ok(key)
    }

    pub fn get(&self, key: u64) -> Option<T> {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&key)
            .cloned()
    }

    pub fn remove(&self, key: u64) -> Option<T> {
        self.inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&key)
    }

    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lowest_key(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .keys()
            .min()
            .copied()
    }

    pub fn clear(&self) -> usize {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let removed = inner.len();
        inner.clear();
        removed
    }
}

#[derive(Debug)]
pub struct HandleRegistry<T: Clone> {
    values: Registry<T>,
    handles: RwLock<HashMap<String, u64>>,
    reverse_handles: RwLock<HashMap<u64, String>>,
    capacity: usize,
    policy: EvictionPolicy,
}

impl<T: Clone> HandleRegistry<T> {
    pub fn new(capacity: usize, policy: EvictionPolicy) -> Self {
        Self {
            values: Registry::new(capacity, policy),
            handles: RwLock::new(HashMap::new()),
            reverse_handles: RwLock::new(HashMap::new()),
            capacity,
            policy,
        }
    }

    pub fn insert(&self, handle: String, value: T) -> Result<String, BindingCoreError> {
        {
            let handles = self
                .handles
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            if handles.contains_key(&handle) {
                return Err(BindingCoreError::HandleAlreadyRegistered(handle));
            }
        }

        if matches!(self.policy, EvictionPolicy::LruLowestKey) {
            while self.values.len() >= self.capacity {
                let Some(lowest_key) = self.values.lowest_key() else {
                    break;
                };
                self.values.remove(lowest_key);
                let mut reverse = self
                    .reverse_handles
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner());
                if let Some(evicted_handle) = reverse.remove(&lowest_key) {
                    self.handles
                        .write()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .remove(&evicted_handle);
                }
            }
        }

        let key = self.values.insert(value)?;
        self.handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(handle.clone(), key);
        self.reverse_handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(key, handle.clone());
        Ok(handle)
    }

    pub fn get(&self, handle: &str) -> Option<T> {
        let key = self
            .handles
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(handle)
            .copied()?;
        self.values.get(key)
    }

    pub fn remove(&self, handle: &str) -> Option<T> {
        let key = self
            .handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(handle)?;
        self.reverse_handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&key);
        self.values.remove(key)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn clear(&self) -> usize {
        self.handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        self.reverse_handles
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        self.values.clear()
    }
}
