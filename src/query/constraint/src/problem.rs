// Copyright 2023 Datafuse Labs.
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

use z3::ast::forall_const;
use z3::ast::Bool;
use z3::ast::Int;
use z3::Context;
use z3::SatResult;
use z3::Solver;

use crate::declare::is_not_null_int;

/// NOTICE: This function is only valid for the predicates that only
/// contain a single variable. For example, `a > 0` is valid, but
/// `a + b > 0` is not.
///
/// Assert that an integer is not null with a given solver.
/// We will check this by adding a new constraint to the solver:
///
///    ∀x (p(x) -> x is not null)
///
/// If this constraint is satisfiable, then the integer is not null.
///
/// # Example
/// ```ignore
/// // a > 0
/// let proposition = Int::new_const(&ctx, "a").gt(&Int::from_i64(&ctx, 0));
/// assert_eq!(assert_int_is_not_null(&ctx, &solver, &Int::new_const(&ctx, "a"), &proposition), SatResult::Sat);
/// ```
pub fn assert_int_is_not_null(
    ctx: &Context,
    solver: &Solver,
    variable: &Int,
    proposition: &Bool,
) -> SatResult {
    let p = forall_const(
        ctx,
        &[variable],
        &[],
        &proposition.implies(&is_not_null_int(ctx, variable)),
    );

    solver.push();
    solver.assert(&p);
    let result = solver.check();
    solver.pop(1);
    result
}