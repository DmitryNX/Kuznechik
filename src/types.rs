pub type Block128 = [u8; 16];
pub type Block256 = [u8; 32];

pub trait Array: Sized {
    type Item;
}

impl Array for Block128 {
    type Item = u8;
}

#[inline]
pub(crate) fn mut_cast_unchecked<T: Array>(slice: &mut [T::Item]) -> &mut T {
    unsafe {
        &mut *(slice.as_mut_ptr() as *mut T)
    }
}
