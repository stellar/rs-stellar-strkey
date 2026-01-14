/// A fixed-capacity vector that stores elements on the stack.
/// Similar to heapless::Vec but defined locally to avoid dependencies.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vec<T, const N: usize> {
    buf: [T; N],
    len: usize,
}

impl<const N: usize> Default for Vec<u8, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Vec<u8, N> {
    /// Creates a new empty vector.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }
}

impl<T, const N: usize> Vec<T, N> {
    /// Returns the number of elements in the vector.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the vector is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the maximum capacity of the vector.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns a slice containing all elements.
    pub fn as_slice(&self) -> &[T] {
        &self.buf[..self.len]
    }

    /// Returns a mutable slice containing all elements.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.buf[..self.len]
    }

    /// Clears the vector, removing all elements.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<T: Copy, const N: usize> Vec<T, N> {
    /// Appends an element to the back of the vector.
    /// Returns Err with the value if the vector is full.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len >= N {
            return Err(value);
        }
        self.buf[self.len] = value;
        self.len += 1;
        Ok(())
    }

    /// Extends the vector with elements from a slice.
    /// Returns Err if there isn't enough capacity.
    pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), ()> {
        if self.len + slice.len() > N {
            return Err(());
        }
        self.buf[self.len..self.len + slice.len()].copy_from_slice(slice);
        self.len += slice.len();
        Ok(())
    }
}

impl<T, const N: usize> core::ops::Deref for Vec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> core::ops::DerefMut for Vec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Vec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<const N: usize> TryFrom<&[u8]> for Vec<u8, N> {
    type Error = ();

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() > N {
            return Err(());
        }
        let mut v = Self::new();
        v.extend_from_slice(slice)?;
        Ok(v)
    }
}

impl<const N: usize> TryFrom<&mut [u8]> for Vec<u8, N> {
    type Error = ();

    fn try_from(slice: &mut [u8]) -> Result<Self, Self::Error> {
        Self::try_from(slice as &[u8])
    }
}

impl<T: core::fmt::Debug, const N: usize> core::fmt::Debug for Vec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

// Implement From<[u8; M]> for Vec<u8, N> where M <= N
// Using a macro since Rust doesn't support generic const constraints like M <= N
macro_rules! impl_from_array {
    ($($m:expr),*) => {
        $(
            impl<const N: usize> From<[u8; $m]> for Vec<u8, N> {
                #[allow(unused_comparisons)]
                fn from(arr: [u8; $m]) -> Self {
                    assert!($m <= N, "array size exceeds Vec capacity");
                    let mut v = Self::new();
                    let _ = v.extend_from_slice(&arr);
                    v
                }
            }
        )*
    };
}

impl_from_array!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);
