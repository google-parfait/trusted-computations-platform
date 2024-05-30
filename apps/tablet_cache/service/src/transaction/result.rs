// Copyright 2024 The Trusted Computations Platform Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::cell::RefCell;

use alloc::rc::Rc;

pub fn create_eventual_result<T: Clone, E: Clone>() -> (ResultHandle<T, E>, ResultSource<T, E>) {
    let core = Rc::new(RefCell::new(ResultCore::<T, E> {
        result: None,
        error: None,
    }));
    (
        ResultHandle::<T, E> { core: core.clone() },
        ResultSource::<T, E> { core },
    )
}

// Holds shared state of the result handler and source.
struct ResultCore<T: Clone, E: Clone> {
    result: Option<T>,
    error: Option<E>,
}

// Enables method caller to later check if the result is available.
pub struct ResultHandle<T: Clone, E: Clone> {
    core: Rc<RefCell<ResultCore<T, E>>>,
}

impl<T: Clone, E: Clone> ResultHandle<T, E> {
    pub fn check_result(&self) -> Option<Result<T, E>> {
        let core = self.core.borrow_mut();
        if core.result.is_some() {
            Some(Ok(core.result.as_ref().unwrap().clone()))
        } else if core.error.is_some() {
            Some(Err(core.error.as_ref().unwrap().clone()))
        } else {
            None
        }
    }
}

// Enables method logic to later set the result to either a value or an error.
pub struct ResultSource<T: Clone, E: Clone> {
    core: Rc<RefCell<ResultCore<T, E>>>,
}

impl<T: Clone, E: Clone> ResultSource<T, E> {
    pub fn set_result(&mut self, result: T) {
        let mut core = self.core.borrow_mut();
        assert!(core.error.is_none() && core.result.is_none());
        core.result = Some(result);
    }

    pub fn set_error(&mut self, error: E) {
        let mut core = self.core.borrow_mut();
        assert!(core.error.is_none() && core.result.is_none());
        core.error = Some(error);
    }
}
